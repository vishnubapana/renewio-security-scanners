import Foundation

// Synthetic insecure fixture for Gitleaks / Semgrep — NOT real credentials.
enum FixtureSecrets {
    static let awsKey = "AKIAIOSFODNN7EXAMPLE"
    static let apiToken = "ghp_exampleTokenShouldBeDetectedByGitleaks0001"
}
