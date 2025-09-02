#xss #csp #nonce #css #disk-cache 

1. Open the page and leak the nonce with css
2. Change location
3. Change the cookie to a script with the leaked nonce
4. Go back in history, the page will have the old nonce but the script will be re-executed with the new cookie -> XSS

https://gist.github.com/sebastianosrt/11cbb86e12682723e4dca598eeb4d110