---
title: "Analysing a Fake Royal Mail Smishing Attack Hidden Behind Cloudflare"
classes: wide
header:
  teaser: /assets/images/Royal-Mail/royal.jpeg
ribbon: DodgerBlue
description: "Exploring a fake Royal Mail smishing attack that uses deceptive SMS and a phishing site hidden behind Cloudflare to steal sensitive information."
categories:
  - Phishing
toc: true
date: 2024-11-24
---

### Analysing a Fake Royal Mail Smishing Attack Hidden Behind Cloudflare

---

### **Introduction**

On 23/11/2024, a user received an SMS claiming to be from Royal Mail:  
*“Royal Mail: You have an update for your parcel delivery, check at Royalmail[dot]delivery-service[dot]info.”* As shown in Fig 1.

After visiting the website, the user realised it was a phishing attempt designed to harvest personal information. The site requested a small token fee for parcel clearance, which raised suspicion, as Royal Mail would never ask for such a fee. While the request seemed odd, it became more convincing for those who were expecting a delivery from Royal Mail. In such situations, if not paying close attention, it would be easy to fall victim to the scam.

![Figure 1](/assets/images/Royal-Mail/SMS-smishing.jpeg)  
*Fig 1: Example of a typical smishing SMS targeting victims.*


The attack begins with a seemingly innocuous SMS, followed by a phishing website that mimics the official Royal Mail service. The site is hidden behind Cloudflare as shown in Fig 2, likely to obscure its true origin and make it harder to trace the attackers or for security enhancement.

![Figure 2](/assets/images/Royal-Mail/URL-redirect-to-cloudflare.png)  
*Fig 2: URL redirection to Cloudflare used by attackers to bypass detection.*

The attacker also gathers users postcode as shown in Fig 3.

![Figure 3](/assets/images/Royal-Mail/Pending-Delivery-postcode.png)  
*Fig 3: Fake pending delivery notice requesting postcode verification.*


### **Attack Stages**

#### **Stage 1: Harvesting PII**

Through the link, the user is prompted to enter their postcode. In the next stage, they are directed to a page requesting confirmation of their address details—something Royal Mail would not typically ask for, as it is not standard practice.

![Figure 4](/assets/images/Royal-Mail/personal-information-havesting.png)  
*Fig 4: Personal information harvesting on a phishing form.*


This form requests the following personal information:  
- **First Name**
- **Last Name**
- **Phone Number**
- **Date of Birth**
- **Home Address**

At this stage, the attackers collect valuable personally identifiable information (PII) as shown in Fig 4, which could be used for identity theft or further targeted attacks.

#### **Stage 2: Harvesting Credit Card Information**

After entering personal details, the victim is shown a page claiming a delivery fee of £1.45 (including VAT). 

![Figure 5](/assets/images/Royal-Mail/Payment-prompt.png)  
*Fig 5: Fake payment prompt designed to steal sensitive financial data.*

The page claims that payment will only be charged upon successful delivery of the parcel, making the request appear more legitimate, as shown in Fig. 5. The small amount requested by the attacker increases the likelihood of the victim agreeing to pay, unaware that they will suffer significant losses if the attacker gains access to their card details.

![Figure 6](/assets/images/Royal-Mail/CVV-card-details-havesting.png)  
*Fig 6: Harvesting CVV and credit card details on a fake payment page.*

The page then asks for credit card details:  
- **Name as it appears on the card**
- **Card Number**
- **Card Expiry Date (MM/YY)**
- **CVV**

This stage is designed to steal credit card information, which can then be used for fraudulent transactions or sold on the dark web. In this case, the attacker attempted to add the victim's card to Apple Pay and make transactions. However, their efforts failed because we stayed one step ahead of them. Our goal was solely to observe and understand how this process works. Please note that the card was added 09:40PM and they try to charge the card 09:45PM.


#### **Last Page: Final Confirmation**

On the final page, the victim is presented with the following message:  


![Figure 7](/assets/images/Royal-Mail/fake-shiping-process.png)  
*Fig 7: Fake shipping process page to deceive the victim.*


*“Your item will be delivered in the next 2-4 business days. It’ll only take a few seconds, we’re just verifying the details that you’ve entered. You may be redirected to your bank to confirm your details.”*


![Figure 8](/assets/images/Royal-Mail/details-credential-sending.png)  
*Fig 9: Credential sent to attacker.*

This final step creates a sense of urgency and legitimacy, potentially redirecting the victim to their bank's verification page or simply reassuring them that the process is normal.

![Figure 8](/assets/images/Royal-Mail/final-message.png)  
*Fig 10: Final fake message displayed to confirm successful payment.*




### **Discovering the Hosted Domain**

Although the fake domain was hidden behind Cloudflare, it was important to trace its origin before it started using Cloudflare as a shield. 

![Figure 9](/assets/images/Royal-Mail/cloudflare.png)  
*Fig 11: Phishing website protected by Cloudflare to evade detection.*


By checking the domain on [Name.com](https://www.name.com), we discovered that the domain was actually registered with [NameSilo](http://www.namesilo.com). While most of the registry details were fake, this allowed us to contact the registrar for domain takedown. However, to take action, we needed evidence that the site was malicious.

![Figure 10](/assets/images/Royal-Mail/registrar-informations.png)  
*Fig 12: Registrar information related to the phishing domain.*

#### **Creating a Fake Disposable Credit Card**

To gather evidence, We created a fake disposable credit card and proceeded to fill in all the required information on the phishing site, following the attacker’s process exactly. After about ten minutes, We noticed the attacker attempted to use the card via Apple Pay. However, the transaction failed because the card was a disposable one and had already been frozen.

![Figure 11](/assets/images/Royal-Mail/apple-pay.jpeg)  
*Fig 13: Apple Pay phishing attempt used in smishing campaigns.*


### **Website Takedown**

Normally, web hosting for such phishing sites is done with PHP, and inserting SQL injections into forms could be considered illegal in its own right. Instead, the best course of action is to report the phishing website directly to the domain registrar. With the evidence at hand, We reached out to NameSilo’s support desk, who promptly provided a form for the phishing site takedown.  

![Figure 12](/assets/images/Royal-Mail/domain-take-down.png)  
*Fig 14: Domain take-down in progress to mitigate further attacks.*


As of this writing, the domain is currently down . We will continue urging the NameSilo team to act swiftly, as this is a clear and sophisticated phishing website. The domain was created on **November 16, 2024**, and is set to expire on **November 16, 2025.** By taking down this domain shortly after its creation, many UK users will be protected from falling victim to this scam, contributing to a safer internet for everyone.


### **Conclusion**

This attack is an example of how smishing (SMS phishing) can exploit the anticipation of a delivery. By masquerading as a trusted service like Royal Mail, the attackers trick victims into providing sensitive personal and financial information. 

It is critical to remain cautious when receiving unsolicited messages, particularly those related to financial transactions or deliveries. Users should avoid clicking on links in unsolicited SMS messages and verify the authenticity of any requests directly with the company involved.

What to do if you are a victim
-----------------------------
If you have already provided your personal or financial information in response to this phishing attempt:


1. Disable your card or frooze it
2. Contact your bank and explain the incident

Also contact:

For suspicious text messages, please send us a screenshot of the message to reportascam@royalmail.com.