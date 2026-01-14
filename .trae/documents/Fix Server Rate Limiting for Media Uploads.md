# Fix Server Rate Limiting for Media Uploads

I have reviewed the files and found a **critical issue** in `server.js` that prevents media uploads from working correctly, even with the client-side button fix.

## The Issue
- **File**: `server.js`
- **Bug**: The rate limiter is set to allow only **10 media chunks per minute**.
- **Impact**: Since file uploads are split into 100KB chunks, any file larger than ~1MB (10 chunks) will have its subsequent chunks rejected by the server. The upload will fail silently, and the recipient will never receive the image/video.

## The Fix
I will update `server.js` to increase the media rate limit to a realistic value that accommodates file splitting.

### `server.js`
- Increase `media` rate limit from `10` to `500` (allowing ~50MB/minute transfer).

## Other Checks
- **`chat.html`**: The previous fix for enabling the Media Button is present and correct.
- **`videochat.html`**: Does not support media sharing (by design), so no changes needed there.
- **`index.html`**: Looks correct.

I will apply the fix to `server.js` now.