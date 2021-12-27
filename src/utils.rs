pub fn is_env_enable(env_name: &str) -> bool {
	match std::env::var(env_name) {
		Ok(s) => {
			vec!["1", "true", "yes", "oui"].contains(&s.to_lowercase().as_str())
		},
		Err(_) => false
	}
}