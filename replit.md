# Hidden Cloud CW Live Tracker

## Overview

This project is a standalone static HTML app for tracking Hidden Cloud Village clan-war rankings. It uses browser storage for local records, Firebase for shared records, and a live JSON endpoint for current rankings.

The app is installable as a Progressive Web App. `manifest.webmanifest` describes the installed app, `sw.js` provides the offline app shell, and the icon files are used by desktop and mobile launchers.

## User preferences

- Keep the existing single-file static-site structure unless a change is required for a requested feature.
- Live rankings should remain network-only so stale data is not presented as current.