# PinIt

A prototype for saving places to lists and sharing trips with friends: pins on a map, notes and photos from everyone on the trip, photo import that builds the stops for you, and a replay of the trip.

## What's here

| Path | What it is |
| --- | --- |
| `src/app.html` | The whole app: one page of HTML, CSS and JavaScript. This is the file to edit. |
| `index.html` | The hosted site, built from `src/app.html` by `./build.sh`. Don't edit it by hand. |
| `config.js` | Settings for the hosted site: the Supabase address and public key, and the Google Maps key. |
| `supabase/schema.sql` | The database: tables, access rules and the functions the app calls. |

The same `src/app.html` runs in three places:

- **The hosted site** (GitHub Pages). `config.js` is present, so shared lists and photos go to Supabase, people join a list from an invite link, and Google Maps loads for everyone.
- **The PinIt page on Claude.** No `config.js`; shared lists use the page's own store, and the map is a preview because pages on Claude can't load Google Maps.
- **A local file.** Everything stays in the browser.

Private lists and private notes always stay in the browser, wherever the app runs.

## Setting up the hosted site

1. **Supabase.** Create a project, then run `supabase/schema.sql` in the SQL editor. Under Authentication → Sign In / Providers, turn on **Allow anonymous sign-ins**.
2. **Config.** Put the project URL and the `anon` public key in `config.js`.
3. **GitHub Pages.** In the repository's Settings → Pages, deploy from the `main` branch, root folder.
4. **Google Maps.** Add the site's address (for example `https://USERNAME.github.io/*`) to the key's allowed websites, then put the key in `config.js`. The key needs the Maps JavaScript API and Places API (New).

## Making changes

Edit `src/app.html`, run `./build.sh`, commit and push. GitHub Pages updates in a minute or two.

## How sharing works on the hosted site

- Each browser gets its own anonymous sign-in. Nobody needs an account; they choose a display name.
- A list is visible only to its members. The invite link carries the list's random id, and opening it adds you as a member.
- Members can add and edit items. Only the person who created a list can delete it.
- Photos are resized and stripped of location data in the browser, then stored in a public bucket under random names.

Known limits of the prototype: clearing a browser's data loses that sign-in (you can rejoin with the link, but you stop being the owner of lists you created), and anyone who has an invite link can join.
