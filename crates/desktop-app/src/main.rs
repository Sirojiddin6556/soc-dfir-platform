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

    let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cas_dir = base_dir.join("data").join("cas");
    let ui_dir = base_dir.join("apps").join("desktop-ui");

    // Spawn embedded local engine-server on a dedicated background thread
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create background Tokio runtime");

        rt.block_on(async move {
            let _ = engine_server::run_embedded_server("127.0.0.1:8080", cas_dir, ui_dir).await;
        });
    });

    // Give server a moment to bind port 8080
    std::thread::sleep(std::time::Duration::from_millis(150));

    // Native Window via Tao
    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("Blue Team Cyber Range & SOC/DFIR Platform")
        .with_inner_size(LogicalSize::new(1440.0, 900.0))
        .with_min_inner_size(LogicalSize::new(1024.0, 700.0))
        .build(&event_loop)?;

    // Native WebView via Wry mounted into the native Tao window
    let webview_data_dir = std::env::temp_dir().join("soc-dfir-webview-data");
    let mut web_context = wry::WebContext::new(Some(webview_data_dir));
    let _webview = WebViewBuilder::new_with_web_context(&mut web_context)
        .with_url("http://127.0.0.1:8080")
        .build(&window)?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            *control_flow = ControlFlow::Exit;
        }
    });
}
