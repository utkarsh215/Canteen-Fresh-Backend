import nodemailer from "nodemailer";
import 'dotenv/config';
async function app(email, subject, text)
{
    try {
        const transporter = nodemailer.createTransport({
            host: process.env.HOST,
            service:process.env.SERVICE,
            port:process.env.EMAIL_PORT,
            secure:true,
            auth:{
                user:process.env.USER,
                pass:process.env.PASS
            }
        });

        await transporter.sendMail({
            from:process.env.USER,
            to:email,
            subject:subject,
            text:text
        });
        console.log("Email sent successfully")

    } catch (error) {
        console.error("Email not sent");
        console.error(error);
    }
}

export default app;