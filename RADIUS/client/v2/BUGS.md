go run .\client\v2\. -c .\client\v2\config.fuzz.yaml          
2026/09/24 14:54:24 [scenario "fuzz-full-suite"] starting (type=fuzz)
2026/09/24 14:54:24 [fuzz] seed=1790250864882885100 iterations=300 strategies=[bit_flip duplicate empty_value length_mismatch message_authenticator_tamper missing_required oversized_value truncate unknown_type]
2026/09/24 14:54:24 [scenario "fuzz-full-suite"] FAILED: [fuzz] baseline health-check failed before fuzzing started: seed packet no longer accepted: got code 3 (Access-Reject)2026/09/24 14:54:24 [scenario "fuzz-message-authenticator-only"] starting (type=fuzz)
2026/09/24 14:54:24 [fuzz] seed=1790250864940107300 iterations=100 strategies=[message_authenticator_tamper]
2026/09/24 14:54:24 [scenario "fuzz-message-authenticator-only"] FAILED: [fuzz] baseline health-check failed before fuzzing started: seed packet no longer accepted: got code 3 (Access-Reject)
2026/09/24 14:54:24 [summary] 2 scenario(s): 0 ok, 2 failed
2026/09/24 14:54:24 one or more scenarios failed: 2 of 2 scenario(s) failed
exit status 1