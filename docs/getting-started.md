# Getting started with Sealift

Sealift is a dashboard for eBay sellers. It brings your listings, payouts, transaction history, account balances and buyer messages together in one place, so you don't have to click through eBay's own pages to see how your stores are doing.

## What you need before signing up

Sealift connects to eBay using your own eBay developer keys. You create a free account on the eBay Developers Program site, make an application ("keyset"), and paste four values into Sealift when you register: App ID (also called Client ID), Dev ID, Cert ID (also called Client Secret), and a RuName (also called a Redirect URL name). This is a one-time setup and takes most people around half an hour.

Using your own keys means your Sealift account talks to eBay as you. Your API usage counts against your own eBay limits, and no other Sealift user shares them.

## Creating your account

Go to the Register page. Enter the email address and password you want to sign in with, then paste the four eBay values. If you are testing with eBay's Sandbox rather than the real marketplace, tick the Sandbox checkbox — Sandbox accounts show fake test data, not your real store.

Your email address is your username. Capitalisation does not matter when you sign in.

## Adding a seller

After you sign in, the first page is "add sellers". Click "authorize through eBay login". A popup opens on eBay asking you to grant Sealift access to your seller account. Sign in to the eBay account you sell from and approve the request.

When the popup finishes, Sealift confirms the seller was added and it appears in the "registered sellers" list on the same page. You can add several seller accounts to one Sealift account — every page then shows a section per seller.

If the popup is blocked by your browser, Sealift tells you so; allow popups for the site and try again. If you leave the eBay window sitting open for more than fifteen minutes before finishing, the authorization link expires and you need to click authorize again.

## Removing a seller

On the "add sellers" page, click the trash icon next to a seller and confirm. This removes the connection between Sealift and that eBay account, along with its stored access tokens. Your listings and sales on eBay itself are not touched.
