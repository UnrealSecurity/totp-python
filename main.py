from totp import Authenticator

def main():
    # create new authenticator
    secret = Authenticator.random_bytes(32)
    auth = Authenticator(secret)

    # dump secret
    details = Authenticator.Details("Example name", "Example description")
    print(auth.dump(details))

if __name__ == "__main__":
    main()