---
tags: 
references:
---
# Shot host
#aws
Exploitation:
- request presigned url with the header: `x-amz-copy-source: /shot-host/1.png`
- perform the put request with an empty body
- get the flag

`midnight{x_Amz_x_1_s3E_iD0r_3vEryWher3}`

# Hackchan
Solves: 
Tags: #race-condition #csrf #flask
## Description
> 
## Overview

## Road to flag


```
case 'delete-account-and-get-flag':
                if current_user.balance >= 999_999_999 and not current_user.is_manager and not current_user.is_admin:
                    current_user.remove()
                    db.session.commit()
                    flash('midnight{********REDACTED********}', 'success')
                    
INSERT INTO users (username, password, is_manager, balance) VALUES
('manager', '********REDACTED********', true, 999999999999);
```

```python
def confirm_transaction():
    with app.app_context():
        pending_transactions = Transaction.query.filter(Transaction.status == 'pending').all()
        for transaction in pending_transactions:
            if transaction.amount <= 10:
                transaction.status = 'confirmed'
            else:
                transaction.status = 'pending-manual-check'
        db.session.commit()

scheduler.add_job(id='confirm_transaction', func=confirm_transaction, trigger="interval", seconds=0.1)

def send_transaction():
    with app.app_context():
        confirmed_transactions = Transaction.query.filter(Transaction.status == 'confirmed').all()

        for transaction in confirmed_transactions:
            sender = User.query.get(transaction.sender_id)
            recipient = User.query.get(transaction.recipient_id)
            if sender and recipient:
                if sender.balance >= transaction.amount:
                    transaction.status = 'sent'
                    if not sender.is_manager:
                        sender.balance -= transaction.amount
                    recipient.balance += transaction.amount
                else:
                    transaction.status = 'rejected'
        db.session.commit()

scheduler.add_job(id='send_transaction', func=send_transaction, trigger="interval", seconds=0.13)

scheduler.start()
```
## Code review
```js
const { chromium } = require('playwright');

(async () => {
  while (true) {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    page.on('dialog', dialog => dialog.accept());

    const now = new Date();
    const formattedDate = now.toISOString();
    process.stdout.write(`${formattedDate} - Task started\n`);

    await page.goto('http://web:8000/');
    await page.fill('#username', 'manager');
    await page.fill('#password', '********REDACTED********');
    await page.click('[type="submit"]');
    await page.goto('http://web:8000/?action=order-problems');

    const orders = await page.locator('xpath=//table//a');
    let ordersCount = await orders.count();
    process.stdout.write(`${formattedDate} - ${ordersCount} new orders\n`);

    if (ordersCount === 0) {
      await page.waitForTimeout(5000);
    } else {
      await orders.first().click();
      process.stdout.write(`${formattedDate} - open order\n`);
      await page.waitForSelector('a[class="btn btn-success"]');
      const problemDescription = await page.locator('xpath=//body//div//p[1]').innerText();
      const homeOrigin = new URL(page.url()).origin;
      const problemWords = problemDescription.split(' ');

      for (const word of problemWords) {
        const urlPattern = /^http:\/\/web:8000\//;
        if (urlPattern.test(word) && word !== homeOrigin) {
          const currentProblem = page.url()
          await page.goto(word);
          await page.waitForTimeout(2000);
          await page.goto(currentProblem);
        }
      }

      await page.click('a[class="btn btn-success"]');
      process.stdout.write(`${formattedDate} - delete order\n`);
      await page.waitForSelector('xpath=//h1[text()="Order Problems List"]');
    }

    await browser.close();
  }
})();

```
## Exploitation

- xss
- csrf

- race condition between confirm and send transaction -> update transaction
```python
case 'create-transaction':
	sender = current_user.id
	recipient_name = request.form.get('recipient')
	if recipient_name:
			if recipient_name != current_user.username:
					recipient = User.query.filter_by(username=recipient_name).first()
					if recipient:
							amount = int(request.form.get('amount'))
							if amount > 0:
									form_data = dict(request.form)
									form_data['amount'] = amount
									del form_data['recipient']
									form_data['recipient_id'] = recipient.id
									transaction = Transaction.update_or_create(current_user.id, form_data) //!!!!
```


```
http://sebb.local:8000/?action=faq&question=Do+you+have+a+press+kit+available+that+includes+company+logos+and+release+templates%3F<script>alert()</script>
```