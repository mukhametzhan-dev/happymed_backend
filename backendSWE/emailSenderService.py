from __future__ import print_function
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from pprint import pprint

# Configuration
configuration = sib_api_v3_sdk.Configuration()
configuration.api_key['api-key'] = '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'  # Replace with your actual Brevo API key

# Create an instance of the API class
api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))

def send_reset_password_email(to_email, to_name, reset_url):
    subject = "Password Reset Request"
    html_content = f"<html><body><p>Please click the link to reset your password: <a href='{reset_url}'>Reset Password</a></p></body></html>"
    sender = {"name": "HappyMed", "email": "happymed@sdu.kz"}
    to = [{"email": to_email, "name": to_name}]
    
    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
        to=to,
        sender=sender,
        subject=subject,
        html_content=html_content
    )

    try:
        api_response = api_instance.send_transac_email(send_smtp_email)
        pprint(api_response)
    except ApiException as e:
        print("Exception when calling SMTPApi->send_transac_email: %s\n" % e)

# Example usage
if __name__ == "__main__":
    to_email = "example@example.com"  # Replace with the recipient's email
    to_name = "Jane Doe"  # Replace with the recipient's name
    reset_url = "http://example.com/reset-password?token=exampletoken"  # Replace with the actual reset URL
    send_reset_password_email(to_email, to_name, reset_url)