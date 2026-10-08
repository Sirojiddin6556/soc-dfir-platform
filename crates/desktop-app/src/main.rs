use std::path::PathBuf;
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};
use wry::WebViewBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    // 1. Resolve Project Root, UI assets, and CAS directory robustly across working directories
    let cur_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    let root_dir = if cur_dir.join("apps").join("desktop-ui").exists() {
        cur_dir
    } else if exe_dir.join("apps").join("desktop-ui").exists() {
        exe_dir
    } else if exe_dir
        .join("..")
        .join("..")
        .join("apps")
        .join("desktop-ui")
        .exists()
    {
        exe_dir.join("..").join("..")
    } else {
        cur_dir
    };

    let ui_dir = root_dir.join("apps").join("desktop-ui");
    let cas_dir = root_dir.join("data").join("cas");
    let db_path = root_dir.join("data").join("case.db");

    // 2. Bind local HTTP / IPC server to port 8080 or dynamic fallback
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create background Tokio runtime");

    let listener = rt
        .block_on(async { engine_server::bind_server(8080).await })
        .expect("Failed to bind TCP listener");

    let port = listener.local_addr()?.port();
    let url = format!("http://127.0.0.1:{}", port);

    // 3. Launch embedded server loop on dedicated background thread
    let ui_dir_clone = ui_dir.clone();
    let server = std::thread::spawn(move || {
        rt.block_on(async move {
            if let Err(e) =
                engine_server::run_server_loop(listener, cas_dir, db_path, ui_dir_clone).await
            {
                tracing::error!("Engine server loop terminated: {}", e);
            }
        });
    });

    // 4. Show the interface in a native window. Without one (no WebView2
    // runtime, no display) the engine keeps running and the interface opens
    // in the default browser instead, so the app still works.
    let window = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_window(&url)));
    let reason = match window {
        Ok(Err(e)) => e.to_string(),
        Err(_) => "the window toolkit panicked".to_string(),
        Ok(Ok(())) => return Ok(()),
    };
    tracing::error!("Native window unavailable ({reason}); serving the interface at {url}");
    println!("The app window could not be opened ({reason}).");
    println!("Open {url} in a browser. Close this console to stop the app.");
    open_in_browser(&url);
    let _ = server.join();
    Ok(())
}

fn run_window(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    // GTK aborts the process instead of returning an error without a display.
    #[cfg(target_os = "linux")]
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return Err("no graphical display".into());
    }

    // Create isolated per-process WebView2 directory to prevent 0x800700AA lock collisions
    let pid = std::process::id();
    let webview_data_dir = std::env::temp_dir().join(format!("soc-dfir-wv-{}", pid));
    let mut web_context = wry::WebContext::new(Some(webview_data_dir));

    // Initialize native Tao desktop window
    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("Blue Team Cyber Range & SOC/DFIR Platform")
        .with_inner_size(LogicalSize::new(1440.0, 900.0))
        .with_min_inner_size(LogicalSize::new(1024.0, 700.0))
        .with_visible(true)
        .build(&event_loop)?;

    // Mount native Wry WebView
    let _webview = WebViewBuilder::new_with_web_context(&mut web_context)
        .with_url(url)
        .build(&window)?;

    window.set_focus();

    // Native event pump
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        let _ = (&_webview, &web_context);

        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            *control_flow = ControlFlow::Exit;
        }
    });
}

/// Opens `url` in the default browser unless SOC_NO_BROWSER=1.
fn open_in_browser(url: &str) {
    if std::env::var("SOC_NO_BROWSER").is_ok_and(|v| v == "1") {
        return;
    }
    #[cfg(target_os = "windows")]
    let opened = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
    #[cfg(target_os = "macos")]
    let opened = std::process::Command::new("open").arg(url).spawn();
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let opened = std::process::Command::new("xdg-open").arg(url).spawn();
    if let Err(e) = opened {
        tracing::warn!("Could not open a browser: {e}");
    }
}
