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
    std::thread::spawn(move || {
        rt.block_on(async move {
            if let Err(e) =
                engine_server::run_server_loop(listener, cas_dir, db_path, ui_dir_clone).await
            {
                tracing::error!("Engine server loop terminated: {}", e);
            }
        });
    });

    // 4. Create isolated per-process WebView2 directory to prevent 0x800700AA lock collisions
    let pid = std::process::id();
    let webview_data_dir = std::env::temp_dir().join(format!("soc-dfir-wv-{}", pid));
    let mut web_context = wry::WebContext::new(Some(webview_data_dir));

    // 5. Initialize native Tao desktop window
    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("Blue Team Cyber Range & SOC/DFIR Platform")
        .with_inner_size(LogicalSize::new(1440.0, 900.0))
        .with_min_inner_size(LogicalSize::new(1024.0, 700.0))
        .with_visible(true)
        .build(&event_loop)?;

    // 6. Mount native Wry WebView
    let _webview = WebViewBuilder::new_with_web_context(&mut web_context)
        .with_url(&url)
        .build(&window)?;

    window.set_focus();

    // 7. Native event pump
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
