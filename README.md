![](https://github.com/hackvertor/shadow-repeater/blob/main/src/main/resources/images/logo.png)

# Shadow Repeater

Shadow Repeater enhances Burp Suite’s Repeater by automatically generating and testing variations of your payloads to uncover potential security weaknesses. Whether you're probing for path traversal, SQL injection, XSS, or other vulnerabilities, Shadow Repeater intelligently mutates your inputs and analyzes responses for anomalies, making it an essential tool for in-depth manual testing and fuzzing. Stay one step ahead by discovering bypasses and alternative attack vectors that might otherwise go unnoticed.

![](https://github.com/hackvertor/shadow-repeater/blob/main/videos/shadow-repeater-ssti-demo.gif)

## Installation instructions

**In Burp Suite Professional, go to Extensions->BApp store and search for Shadow Repeater. Click the install button and then navigate to the installed tab then select Shadow Repeater and check the "Use AI" checkbox in the Extension tab.**

![](https://github.com/hackvertor/shadow-repeater/blob/main/screenshots/shadow-repeater-install-screenshot.png)

## How to use

By default Shadow repeater gets invoked on the 5th repeater request you make and it requires a parameter or header to be changed. You simply try to hack a target by altering the request in some way. In the background Shadow repeater will send variations and look for differences in the response. When it's found something interesting it will send it to the organiser for inspection.