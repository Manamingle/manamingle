import { MailerSend, EmailParams, Sender, Recipient } from "mailersend";

const mailerSend = new MailerSend({
    apiKey: process.env.API_KEY,
});

const sentFrom = new Sender("manaminglee@gmail.com", "Your name");

const recipients = [
    new Recipient("manaminglee@gmail.com", "Your Client")
];

const personalization = [
  {
    email: "manaminglee@gmail.com",
    data: {
      CODE: ''
    },
  }
];

const emailParams = new EmailParams()
    .setFrom(sentFrom)
    .setTo(recipients)
    .setReplyTo(sentFrom)
    .setSubject("This is a Subject")
    .setTemplateId('x2p03470ww7gzdrn')
    .setPersonalization(personalization);

await mailerSend.email.send(emailParams);