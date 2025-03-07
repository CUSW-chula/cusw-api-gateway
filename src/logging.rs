use std::collections::HashMap;

use tracing_loki::url;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub async fn init_tracing() {
    let loki_url = "http://loki:3100/loki/api/v1/push"
        .parse::<url::Url>()
        .expect("Invalid Loki URL");

    let mut labels: HashMap<String, String> = HashMap::new();
    labels.insert("service".to_string(), "gateway".to_string()); // Ensure both are Strings

    let (loki_layer, task) =
        tracing_loki::layer(loki_url, labels, HashMap::<String, String>::new())
            .expect("Failed to initialize Loki logging");

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().json()) // JSON logs
        .with(tracing_subscriber::EnvFilter::new("info")) // Log level
        .with(loki_layer)
        .init();

    tokio::spawn(task);
}
