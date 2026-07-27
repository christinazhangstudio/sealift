# Account and security

## How Sealift signs you in

You sign in with the email address and password you chose at registration. Your password is stored only as an argon2 hash and is verified on the server; it is never sent back to the browser. Sessions last 24 hours, after which you sign in again.

Signing out immediately invalidates that session everywhere, not just in the tab you were using.

## Changing your password

Open Settings, enter your current password and the new one. Changing your password does not sign out your other devices automatically.

## Resetting a forgotten password

On the sign-in page, use "Forgot password?" and enter your email address. If an account exists, Sealift sends a link that lets you choose a new password. The link works once and expires after an hour. For privacy, the page shows the same confirmation whether or not an account exists for that address.

## Your eBay keys

Sealift stores the eBay developer keyset you provided so it can talk to eBay on your behalf, and it stores an access token per seller you authorize. You can view and update the keyset in Settings.

Treat your Cert ID like a password — anyone who has it can act as your eBay application. If you think it has leaked, rotate it in the eBay Developers Program portal and paste the new value into Sealift's Settings page.

## Multiple sellers, one account

One Sealift account can hold several eBay seller accounts. Every seller you add is scoped to your Sealift account; other Sealift users cannot see your sellers, listings, payouts, notes or messages.

## Guest mode

Signing in as a guest lets you look around without creating an account. Guests can try the AI listing description generator a couple of times, but cannot connect eBay sellers or see real data. Create an account to use the full dashboard.

## Deleting your account

The Admin page permanently deletes your Sealift account: your seller connections, stored tokens, notes and notifications. It cannot be undone. Your eBay account and listings are unaffected — deleting from Sealift only removes Sealift's access.
