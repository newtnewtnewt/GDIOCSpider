# Setup Google Drive API:

1. Go to the Google Cloud Console.
2. Create a new project and enable the Google Drive API.
3. Create a service account [using the steps here](https://developers.google.com/workspace/guides/create-credentials)
4. Use a library like google-auth and google-api-python-client to authenticate and interact with the API.

# Getting User Credentials

gcloud auth application-default login

https://cloud.google.com/sdk/docs/install

https://developers.google.com/drive/api/quickstart/python

You have to use the command above: gcloud auth application-default login
to install a token.json. This is placed at the root directory.

Credentials is created inside of GCP in the OAuth flow

