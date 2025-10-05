#![cfg(test)]

use hamrah_api::db::schema::{validate_link_state, LinkState};

#[test]
fn test_link_state_valid_values() {
    // Allowed states should parse successfully
    let s1 = validate_link_state("active").expect("active should be valid");
    let s2 = validate_link_state("archived").expect("archived should be valid");

    assert_eq!(s1, LinkState::Active);
    assert_eq!(s2, LinkState::Archived);

    // Ensure string mappings are stable
    assert_eq!(s1.as_str(), "active");
    assert_eq!(s2.as_str(), "archived");
    assert_eq!(s1.to_string(), "active");
    assert_eq!(s2.to_string(), "archived");
}

#[test]
fn test_link_state_case_insensitive() {
    // Parser is case-insensitive
    assert_eq!(
        validate_link_state("ACTIVE").expect("uppercase ACTIVE should be valid"),
        LinkState::Active
    );
    assert_eq!(
        validate_link_state("ArChIvEd").expect("mixed-case ArChIvEd should be valid"),
        LinkState::Archived
    );
}

#[test]
fn test_link_state_rejects_invalid_values() {
    // These values existed historically but are not allowed by the schema's CHECK constraint
    for invalid in ["new", "pending", "deleted", "inactive", "", "   "] {
        let err = validate_link_state(invalid).expect_err("invalid state should be rejected");
        // Error message should clearly enumerate allowed values
        assert!(
            err.contains("Invalid link state"),
            "expected error to indicate invalid state; got: {}",
            err
        );
        assert!(
            err.contains("active") && err.contains("archived"),
            "expected error to list allowed states; got: {}",
            err
        );
    }
}

#[test]
fn test_link_state_all_matches_expected() {
    // Ensure central list of allowed states remains in sync with DB CHECK constraint
    let all = LinkState::all();
    assert_eq!(all, &["active", "archived"]);
}

#[test]
fn test_patch_invalid_state_validation_message() {
    // The PATCH /v1/links/{id} handler uses validate_link_state; emulate that path here by
    // validating the exact message we expect to be surfaced via AppError::bad_request.
    let invalid = "deleted";
    let err = validate_link_state(invalid).expect_err("deleted should be invalid");
    // The handler forwards this exact message to AppError::bad_request, so it must be clear
    // and actionable in logs and client responses.
    assert!(
        err.starts_with("Invalid link state"),
        "unexpected error prefix: {}",
        err
    );
    assert!(
        err.contains("'deleted'"),
        "should include the offending value; got: {}",
        err
    );
    assert!(
        err.contains("active") && err.contains("archived"),
        "should enumerate allowed states; got: {}",
        err
    );
}
