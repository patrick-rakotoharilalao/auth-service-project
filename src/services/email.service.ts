import nodemailer from 'nodemailer';
import { envConfig } from '../config/env.config';
import logger from '../utils/logger';

/**
 * Email Service
 * Handles sending emails using nodemailer
 */
export class EmailService {
    private static transporter: nodemailer.Transporter | null = null;

    /**
     * Initialize the email transporter
     * Call this once at app startup
     */
    static initialize() {
        try {
            const { host, port, secure, user, password } = envConfig.emailConfig;

            // Only include auth if both user and password are provided
            const transporterConfig: any = {
                host,
                port,
                secure, // true for 465, false for other ports
            };

            // Only add auth if credentials are provided
            if (user && password) {
                transporterConfig.auth = {
                    user,
                    pass: password,
                };
            } else {
                logger.warn('Email credentials not provided. Email service will not work properly.', {
                    hasUser: !!user,
                    hasPassword: !!password,
                });
            }

            this.transporter = nodemailer.createTransport(transporterConfig);

            logger.info('Email transporter initialized', {
                host,
                port,
                secure,
                hasAuth: !!(user && password),
            });
        } catch (error: any) {
            logger.error('Failed to initialize email transporter', {
                error: error.message,
            });
            throw error;
        }
    }

    /**
     * Send password reset email
     * @param to - Recipient email address
     * @param resetLink - Password reset link with token
     */
    static async sendPasswordResetEmail(to: string, resetLink: string): Promise<void> {
        if (!this.transporter) {
            throw new Error('Email transporter not initialized. Call EmailService.initialize() first.');
        }

        // Check if credentials are configured
        if (!envConfig.emailConfig.user || !envConfig.emailConfig.password) {
            throw new Error('SMTP credentials not configured. Please set SMTP_USER and SMTP_PASSWORD in your .env file.');
        }

        const mailOptions = {
            from: `"${envConfig.emailConfig.fromName}" <${envConfig.emailConfig.fromEmail}>`,
            to,
            subject: 'Reset Your Password',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Password Reset</title>
                </head>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background-color: #f4f4f4; padding: 20px; border-radius: 5px;">
                        <h2 style="color: #333;">Password Reset Request</h2>
                        <p>Hello,</p>
                        <p>You requested to reset your password. Click the button below to reset it:</p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="${resetLink}" 
                               style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                                Reset Password
                            </a>
                        </div>
                        <p>Or copy and paste this link into your browser:</p>
                        <p style="word-break: break-all; color: #666; font-size: 12px;">${resetLink}</p>
                        <p style="color: #999; font-size: 12px; margin-top: 30px;">
                            This link will expire in ${envConfig.tokenConfig.resetPasswordTokenTTLHours} hour(s).
                            If you didn't request this, please ignore this email.
                        </p>
                    </div>
                </body>
                </html>
            `,
            text: `
                Password Reset Request
                
                Hello,
                
                You requested to reset your password. Click the link below to reset it:
                
                ${resetLink}
                
                This link will expire in ${envConfig.tokenConfig.resetPasswordTokenTTLHours} hour(s).
                If you didn't request this, please ignore this email.
            `,
        };

        try {
            const info = await this.transporter.sendMail(mailOptions);
            logger.info('Password reset email sent successfully', {
                to,
                messageId: info.messageId,
            });
        } catch (error: any) {
            logger.error('Failed to send password reset email', {
                to,
                error: error.message,
            });
            throw new Error(`Failed to send email: ${error.message}`);
        }
    }

    /**
     * Verify email transporter connection
     * Useful for testing email configuration
     */
    static async verifyConnection(): Promise<boolean> {
        if (!this.transporter) {
            throw new Error('Email transporter not initialized');
        }

        try {
            await this.transporter.verify();
            logger.info('Email transporter connection verified');
            return true;
        } catch (error: any) {
            logger.error('Email transporter verification failed', {
                error: error.message,
            });
            return false;
        }
    }
}
