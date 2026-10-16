use super::{StartupLock, remove_stale_session_sockets, remove_stale_socket};
use std::{
    ffi::CString,
    fs,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    sync::mpsc,
    thread,
    time::Duration,
};

#[test]
fn recursively_removes_stale_owned_sockets_without_following_symlinks() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("socket directory should be private");
    let uid = fs::metadata(directory.path())
        .expect("socket directory metadata should be readable")
        .uid();

    let top_level = directory.path().join("top.sock");
    drop(UnixListener::bind(&top_level).expect("top-level stale socket should bind"));

    let nested = directory.path().join("cladding");
    fs::create_dir(&nested).expect("nested socket directory should be created");
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700))
        .expect("nested socket directory should be private");
    let nested_socket = nested.join("github.sock");
    drop(UnixListener::bind(&nested_socket).expect("nested stale socket should bind"));

    let replaced_socket = nested.join("replaced.sock");
    drop(UnixListener::bind(&replaced_socket).expect("replaceable socket should bind"));
    fs::remove_file(&replaced_socket).expect("old socket should be replaced");
    fs::write(&replaced_socket, "replacement")
        .expect("replacement file should be written at the socket path");

    let active_socket = nested.join("active.sock");
    let active_listener = UnixListener::bind(&active_socket).expect("active socket should bind");

    let unrelated_file = nested.join("notes.txt");
    fs::write(&unrelated_file, "keep").expect("unrelated file should be written");
    let unrelated_directory = nested.join("cache");
    fs::create_dir(&unrelated_directory).expect("unrelated directory should be created");

    let outside = tempfile::tempdir().expect("outside directory should be created");
    fs::set_permissions(outside.path(), fs::Permissions::from_mode(0o700))
        .expect("outside directory should be private");
    let outside_socket = outside.path().join("outside.sock");
    drop(UnixListener::bind(&outside_socket).expect("outside stale socket should bind"));
    let directory_symlink = directory.path().join("linked");
    std::os::unix::fs::symlink(outside.path(), &directory_symlink)
        .expect("directory symlink should be created");

    remove_stale_session_sockets(directory.path(), uid)
        .expect("startup cleanup should scan nested directories");

    assert!(
        !top_level.exists(),
        "top-level stale socket should be removed"
    );
    assert!(
        !nested_socket.exists(),
        "nested stale socket should be removed"
    );
    assert_eq!(
        fs::read(&replaced_socket).expect("replacement path should remain readable"),
        b"replacement",
        "a replaced socket path should be preserved"
    );
    assert!(active_socket.exists(), "active socket should be preserved");
    assert!(UnixStream::connect(&active_socket).is_ok());
    assert!(
        unrelated_file.exists(),
        "unrelated file should be preserved"
    );
    assert!(
        unrelated_directory.is_dir(),
        "unrelated directory should be preserved"
    );
    assert!(
        directory_symlink
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(
        outside_socket.exists(),
        "cleanup must not follow a directory symlink"
    );

    drop(active_listener);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn preserves_active_socket_when_directory_moves_after_liveness_path_resolution() {
    let directory = tempfile::Builder::new()
        .prefix("bf66-")
        .tempdir_in("/tmp")
        .expect("temporary directory should be created");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("socket directory should be private");
    let uid = fs::metadata(directory.path())
        .expect("socket directory metadata should be readable")
        .uid();

    let nested = directory.path().join("cladding");
    fs::create_dir(&nested).expect("nested socket directory should be created");
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700))
        .expect("nested socket directory should be private");
    let socket = nested.join("active.sock");
    let listener = UnixListener::bind(&socket).expect("active socket should bind");
    let moved = directory.path().join("moved");
    let parent =
        super::open_socket_directory(&nested).expect("nested socket directory should open");
    let name = CString::new("active.sock").expect("socket name should not contain a null byte");

    let removed = super::remove_stale_socket_at_with_probe(
        &parent,
        &name,
        &socket,
        uid,
        |parent_fd, name, metadata| {
            super::probe_socket_via_resolved_path(
                parent_fd,
                name,
                metadata,
                super::pinned_directory_path,
                || {
                    fs::rename(&nested, &moved)
                        .expect("directory should move after path resolution");
                },
            )
        },
    )
    .expect("cleanup should preserve a socket when its path moves");

    assert!(!removed, "cleanup must preserve the moved active socket");
    assert!(moved.join("active.sock").exists());
    assert!(
        UnixStream::connect(moved.join("active.sock")).is_ok(),
        "active listener should remain reachable at its moved path"
    );
    drop(listener);
}

#[test]
fn preserves_outside_sockets_when_nested_directory_is_replaced_after_open() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("socket directory should be private");
    let uid = fs::metadata(directory.path())
        .expect("socket directory metadata should be readable")
        .uid();

    let nested = directory.path().join("cladding");
    fs::create_dir(&nested).expect("nested socket directory should be created");
    let nested_socket = nested.join("inside.sock");
    drop(UnixListener::bind(&nested_socket).expect("nested stale socket should bind"));

    let outside = tempfile::tempdir().expect("outside directory should be created");
    fs::set_permissions(outside.path(), fs::Permissions::from_mode(0o700))
        .expect("outside directory should be private");
    let outside_socket = outside.path().join("outside.sock");
    drop(UnixListener::bind(&outside_socket).expect("outside stale socket should bind"));

    let detached = directory.path().join("detached");
    let root = super::open_socket_directory(directory.path())
        .expect("session socket directory should open");
    let mut replaced = false;
    super::remove_stale_session_sockets_at(&root, directory.path(), uid, &mut |path| {
        if path == nested && !replaced {
            fs::rename(path, &detached).expect("opened nested directory should be detached");
            std::os::unix::fs::symlink(outside.path(), path)
                .expect("nested path should become a symlink to the outside directory");
            replaced = true;
        }
    })
    .expect("cleanup should remain confined to opened directories");

    assert!(replaced, "test should replace the opened nested directory");
    assert!(
        nested.symlink_metadata().unwrap().file_type().is_symlink(),
        "replacement symlink should remain"
    );
    assert!(
        !detached.join("inside.sock").exists(),
        "cleanup should remove the stale socket from the pinned directory"
    );
    assert!(
        outside_socket.exists(),
        "cleanup must preserve a socket outside the configured directory"
    );
}

#[test]
fn preserves_session_sockets_owned_by_another_uid() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("socket directory should be private");
    let uid = fs::metadata(directory.path())
        .expect("socket directory metadata should be readable")
        .uid();
    let socket = directory.path().join("foreign.sock");
    drop(UnixListener::bind(&socket).expect("foreign socket should bind"));

    remove_stale_session_sockets(directory.path(), uid ^ 1)
        .expect("cleanup should skip sockets with a different owner");

    assert!(
        socket.exists(),
        "a socket owned by another UID should remain"
    );
}

#[test]
fn serializes_stale_socket_cleanup_through_listener_bind() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("control directory should be private");
    let uid = std::fs::metadata(directory.path())
        .expect("control directory metadata should be readable")
        .uid();
    let socket = directory.path().join("control.sock");

    drop(UnixListener::bind(&socket).expect("stale test socket should bind"));
    let first_lock = StartupLock::acquire(&socket, uid).expect("first startup should lock");
    assert!(
        remove_stale_socket(&socket, uid).expect("stale socket should be removed"),
        "the first startup should remove the disconnected socket"
    );
    let listener = UnixListener::bind(&socket).expect("first startup should bind listener");

    let socket_for_second = socket.clone();
    let (started_sender, started_receiver) = mpsc::channel();
    let (finished_sender, finished_receiver) = mpsc::channel();
    let second_start = thread::spawn(move || {
        started_sender
            .send(())
            .expect("test should observe the second start");
        let _lock = StartupLock::acquire(&socket_for_second, uid)
            .expect("second startup should acquire the lock after the first binds");
        let removed = remove_stale_socket(&socket_for_second, uid)
            .expect("active socket check should succeed");
        let bind_failed = UnixListener::bind(&socket_for_second).is_err();
        finished_sender
            .send((removed, bind_failed))
            .expect("test should observe the second start result");
    });

    started_receiver
        .recv()
        .expect("second startup should reach the lock");
    assert!(
        finished_receiver
            .recv_timeout(Duration::from_millis(50))
            .is_err(),
        "second startup must wait while the first holds the lock through bind"
    );
    drop(first_lock);

    assert_eq!(
        finished_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("second startup should continue after the first binds"),
        (false, true),
        "second startup must preserve the active socket and fail to bind"
    );
    second_start
        .join()
        .expect("second startup thread should finish");
    assert!(
        UnixStream::connect(&socket).is_ok(),
        "first startup's listener should remain reachable"
    );
    drop(listener);
}
