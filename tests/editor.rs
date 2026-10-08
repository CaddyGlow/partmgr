#![cfg(feature = "std")]

use partmgr::{
    editor::Editor,
    guid::Guid,
    layout::{DiskLayout, Geometry, GptLayout, LbaRange},
    payload::FilesystemResize,
};
use std::io;
fn editor() -> Editor {
    let mut layout = GptLayout::initialize(
        Geometry::new(512 * 256, 512).unwrap(),
        Guid::from_bytes([1; 16]),
        128,
        128,
    )
    .unwrap();
    layout
        .create(
            1,
            Guid::from_bytes([2; 16]),
            Guid::from_bytes([3; 16]),
            LbaRange::new(40, 100).unwrap(),
        )
        .unwrap();
    Editor::new(DiskLayout::Gpt(layout))
}
#[test]
fn failed_boundary_edit_leaves_layout_and_review_unchanged() {
    let mut editor = editor();
    assert!(
        editor
            .set_boundary(1, LbaRange::new(1, 100).unwrap())
            .is_err()
    );
    assert!(editor.changes().is_empty());
    let DiskLayout::Gpt(layout) = editor.proposed() else {
        panic!("GPT")
    };
    assert_eq!(
        layout.entries()[0].range().unwrap(),
        LbaRange::new(40, 100).unwrap()
    );
}
struct Shrink(bool);
impl FilesystemResize for Shrink {
    fn shrink(&mut self, _: u64) -> io::Result<()> {
        self.0 = true;
        Err(io::Error::other("filesystem failure"))
    }
    fn grow(&mut self, _: u64) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn managed_shrink_never_commits_when_filesystem_fails() {
    let mut editor = editor();
    let mut fs = Shrink(false);
    assert!(
        editor
            .managed_resize(1, LbaRange::new(40, 80).unwrap(), &mut fs, |_| panic!(
                "must not commit"
            ))
            .is_err()
    );
    assert!(fs.0);
    assert!(editor.changes().is_empty());
}

struct Ordered {
    events: std::rc::Rc<std::cell::RefCell<Vec<&'static str>>>,
    fail_grow: bool,
}
impl FilesystemResize for Ordered {
    fn shrink(&mut self, _: u64) -> io::Result<()> {
        self.events.borrow_mut().push("shrink");
        Ok(())
    }
    fn grow(&mut self, _: u64) -> io::Result<()> {
        self.events.borrow_mut().push("grow");
        if self.fail_grow {
            Err(io::Error::other("grow"))
        } else {
            Ok(())
        }
    }
}
#[test]
fn successive_managed_commits_use_new_baseline_and_report_grow_failure() {
    let mut editor = editor();
    let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut fs = Ordered {
        events: events.clone(),
        fail_grow: false,
    };
    editor
        .managed_resize(1, LbaRange::new(40, 80).unwrap(), &mut fs, |_| {
            events.borrow_mut().push("commit shrink");
            Ok(())
        })
        .unwrap();
    assert_eq!(&*events.borrow(), &["shrink", "commit shrink"]);
    fs.fail_grow = true;
    assert!(
        editor
            .managed_resize(1, LbaRange::new(40, 90).unwrap(), &mut fs, |plan| {
                let old = plan.stages()[0].writes()[0].expected();
                assert_eq!(u64::from_le_bytes(old[40..48].try_into().unwrap()), 79);
                events.borrow_mut().push("commit grow");
                Ok(())
            })
            .is_err()
    );
    assert_eq!(
        &*events.borrow(),
        &["shrink", "commit shrink", "commit grow", "grow"]
    );
    let DiskLayout::Gpt(layout) = editor.proposed() else {
        panic!("GPT")
    };
    assert_eq!(layout.entries()[0].range().unwrap().end(), 90);
    assert_eq!(editor.changes().len(), 2);
}
#[test]
fn pending_boundary_edits_cannot_bypass_managed_prerequisites() {
    let mut editor = editor();
    editor
        .set_boundary(1, LbaRange::new(40, 80).unwrap())
        .unwrap();
    let mut fs = Shrink(false);
    assert!(
        editor
            .managed_resize(1, LbaRange::new(40, 70).unwrap(), &mut fs, |_| panic!(
                "commit"
            ))
            .is_err()
    );
    assert!(!fs.0);
}

#[test]
fn boundary_commit_rereads_and_allows_subsequent_managed_resize() {
    use partmgr::{
        codec,
        storage::{FileStorage, StorageReader},
    };
    let mut editor = editor();
    let image = tempfile::NamedTempFile::new().unwrap();
    image.as_file().set_len(512 * 256).unwrap();
    let mut disk = FileStorage::open(image.path()).unwrap();
    let initialization =
        codec::initialize_plan(&StorageReader::new(&disk).unwrap(), editor.proposed()).unwrap();
    codec::commit_and_inspect(&initialization, &mut disk, 512).unwrap();
    editor
        .set_boundary(1, LbaRange::new(40, 90).unwrap())
        .unwrap();
    editor.commit_boundary_only(&mut disk).unwrap();
    let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut fs = Ordered {
        events,
        fail_grow: false,
    };
    editor
        .managed_resize(1, LbaRange::new(40, 80).unwrap(), &mut fs, |plan| {
            codec::commit_and_inspect(plan, &mut disk, 512)?;
            Ok(())
        })
        .unwrap();
    let actual = partmgr::error::inspect(&StorageReader::new(&disk).unwrap(), 512).unwrap();
    let DiskLayout::Gpt(g) = actual else {
        panic!("GPT")
    };
    assert_eq!(g.entries()[0].range().unwrap().end(), 80);
}
#[test]
fn uncertain_commit_requires_reinspection_before_editor_reuse() {
    let mut editor = editor();
    let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut fs = Ordered {
        events,
        fail_grow: false,
    };
    let error = editor
        .managed_resize(1, LbaRange::new(40, 80).unwrap(), &mut fs, |_| {
            Err(partmgr::storage::CommitError::Interrupted {
                completed_stages: Vec::new(),
                stage: "backup".into(),
                durability_uncertain: true,
                source: io::Error::other("flush"),
            }
            .into())
        })
        .unwrap_err();
    assert!(matches!(error, partmgr::error::Error::PartialCommit(_)));
    assert!(
        editor
            .set_boundary(1, LbaRange::new(40, 70).unwrap())
            .is_err()
    );
    assert!(editor.boundary_only_plan().is_err());
}
