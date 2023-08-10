# Authenticate to Google APIs using a service account with domain-wide delegation

This script is designed to obtain Google API credentials for impersonating a specific user via a service account with domain-wide delegation. The unique aspect of this implementation is that it doesn't require any service account keys or JSON files to be used, thus improving security.

The code is intended to be executed within Google Cloud platforms like Google Cloud Function, Google Cloud Run, or Google Compute Engine instance. The premise is that a service account attached to the executing instance is different from the service account used for impersonation. Modify the code as needed to fit your specific use case.

# Prerequisites:

- Domain-Wide Delegation: Set up domain-wide delegation for a new or existing service account. This script operates on the assumption that the service account with domain-wide delegation is distinct from the service account running this script.
- Enable Necessary APIs: Turn on the "IAM Service Account Credentials API" for your project. Also, ensure that any other APIs you plan to access with this service account are enabled.
- Assign Roles: Give the "Service Account Token Creator" role to the service account that will execute this script. This ensures it has the required permissions to generate tokens.
- Environment Setup: Define the following environment variables:
  - SERVICE_ACCOUNT_EMAIL: The email of the service account that has domain-wide delegation.
  - USER_EMAIL_TO_IMPERSONATE: The email of the user you're attempting to impersonate.
  - GOOGLE_API_SCOPES: A comma-separated list of the Google API scopes needed. For example, "https://www.googleapis.com/auth/drive,https://www.googleapis.com/auth/calendar".

# Output:
Upon successful execution, the script returns a google.oauth2.credentials.Credentials object, which represents the Google API credentials for the impersonated user.
