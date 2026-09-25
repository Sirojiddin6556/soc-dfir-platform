CREATE TABLE IF NOT EXISTS ctf_challenge_answers (
    challenge_id TEXT PRIMARY KEY REFERENCES challenges(id) ON DELETE CASCADE,
    expected_flag_sha256 TEXT NOT NULL
);
