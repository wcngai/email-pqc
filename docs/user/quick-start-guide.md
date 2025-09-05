# PQC Email - User Quick Start Guide

## Welcome to Quantum-Safe Email

The Post-Quantum Cryptography (PQC) email system protects your email communications against future quantum computing threats. This guide will help you get started quickly and understand the key features.

## What's New

Your email experience remains exactly the same, with these important security enhancements:

- **Quantum-Resistant Encryption**: Your emails are protected against quantum computers
- **Hybrid Security**: Uses both post-quantum and traditional encryption for maximum protection
- **Seamless Integration**: Works transparently with your existing Outlook workflow
- **Visual Security Indicators**: Clear badges show when emails are quantum-safe

## Visual Indicators

### Security Badges

When composing or reading emails, look for these security indicators:

| Icon | Status | Description |
|------|--------|-------------|
| 🔒 | **Quantum-Safe** | Email is protected with post-quantum cryptography |
| 🔐 | **Hybrid Protected** | Email uses both quantum-safe and traditional encryption |
| 🔓 | **Traditional Encryption** | Email uses standard encryption only |
| ⚠️ | **Unencrypted** | Email is not encrypted (rare - will prompt you) |

### Status Messages

- **"Quantum-Safe Email Ready"** - Recipient supports PQC encryption
- **"Hybrid Mode Active"** - Using both PQC and traditional encryption
- **"Traditional Encryption"** - Recipient doesn't support PQC yet
- **"Encryption Required"** - Company policy requires encryption for this recipient

## Daily Workflow

### Sending Emails

1. **Compose as Usual**
   - Open Outlook and create a new email
   - Add recipients, subject, and content normally
   - The system automatically detects recipient capabilities

2. **Check Security Status**
   - Look for the security badge before sending
   - Green indicators mean quantum-safe protection
   - Yellow indicates traditional encryption
   - Red requires attention

3. **Send with Confidence**
   - Click Send - no additional steps required
   - The system automatically applies the best available encryption
   - You'll see a confirmation with security details

### Reading Emails

1. **Automatic Decryption**
   - Encrypted emails open automatically
   - No passwords or additional steps needed
   - Security badge shows protection level used

2. **Reply with Same Security**
   - Replies maintain the same encryption level
   - System remembers recipient preferences
   - Forward options preserve security settings

## Understanding Encryption Modes

### Quantum-Safe Mode 🔒
- **Best Protection**: Resistant to quantum computer attacks
- **When Used**: Both you and recipient have PQC capabilities
- **Performance**: Slightly slower than traditional (usually unnoticeable)
- **Compatibility**: Works with all modern email systems

### Hybrid Mode 🔐
- **Maximum Compatibility**: Works with all recipients
- **Double Protection**: Both quantum-safe AND traditional encryption
- **When Used**: Default mode for maximum security
- **File Size**: Slightly larger encrypted messages

### Traditional Mode 🔓
- **Legacy Support**: For recipients without PQC support
- **Automatic Fallback**: System switches automatically when needed
- **Still Secure**: Uses strong traditional encryption
- **Temporary**: Recipients are gradually upgrading to PQC

## Common Scenarios

### Sending to External Partners

**Scenario**: Sending sensitive financial data to external auditor
```
✅ What You'll See: "Quantum-Safe Email Ready" 
✅ Action: Send normally - full PQC protection applied
✅ Result: Email encrypted with ML-KEM-768 + ML-DSA-65
```

**Scenario**: Sending to client who hasn't upgraded yet
```
⚠️ What You'll See: "Traditional Encryption - Recipient Upgrading"
✅ Action: Send normally - strong traditional encryption used
✅ Result: Email encrypted with RSA-OAEP + RSA-PSS
```

### Internal Company Emails

**Scenario**: Sending quarterly report to executive team
```
✅ What You'll See: "Hybrid Mode Active - Maximum Protection"
✅ Action: Send normally - dual encryption applied
✅ Result: Protected against current AND future threats
```

**Scenario**: Regular team communication
```
✅ What You'll See: "Quantum-Safe Email Ready"
✅ Action: Send normally - optimized PQC encryption
✅ Result: Fast quantum-safe protection
```

### Handling Attachments

**Large Documents**:
- System automatically handles encryption
- No file size limits for encryption
- Compression applied when beneficial
- Password protection not needed

**Sensitive Files**:
- Enhanced protection for classified attachments
- Automatic classification detection
- Additional audit logging
- Retention policy enforcement

## Troubleshooting

### Common Questions

**Q: "My email is taking longer to send"**
- A: Post-quantum encryption requires slightly more processing time
- This is normal and typically adds less than 2 seconds
- Performance improves over time as system learns your patterns

**Q: "I see a warning about encryption"**
- A: This means the recipient cannot receive encrypted email
- Contact IT support - this should be rare
- Use alternative communication method for sensitive data

**Q: "The security badge shows yellow instead of green"**
- A: Yellow means traditional encryption (still very secure)
- This happens when recipient doesn't support PQC yet
- Your email is still protected with strong encryption

**Q: "I need to send an urgent unencrypted email"**
- A: This is typically blocked by company policy
- Contact your manager or IT support for exception
- Emergency procedures are available for critical situations

### Getting Help

**Self-Service**:
- Check the security badge first
- Try sending to a different recipient
- Restart Outlook if badges aren't appearing

**IT Support**:
- Email: it-support@company.com
- Phone: +1-555-IT-HELP
- Internal Chat: #it-support
- Emergency: +1-555-EMERGENCY

**When to Contact Support**:
- Encryption errors persist
- Security badges missing
- Unable to read encrypted emails
- Performance significantly degraded

## Security Best Practices

### Do's ✅

- **Trust the System**: Let PQC handle encryption automatically
- **Check Security Badges**: Verify protection level before sending sensitive data
- **Report Issues Promptly**: Contact IT if anything seems wrong
- **Keep Outlook Updated**: Install updates when prompted
- **Use Strong Passwords**: Protect your Outlook account

### Don'ts ❌

- **Don't Disable Encryption**: Even if it seems slower
- **Don't Share Certificates**: Keep your digital certificates private
- **Don't Ignore Warnings**: Always investigate security alerts
- **Don't Use Workarounds**: Contact IT instead of bypassing security
- **Don't Panic**: The system is designed to protect you automatically

## Training Resources

### Quick Reference Card
- Download: [PQC Email Quick Reference Card (PDF)](./pqc-email-quickref.pdf)
- Print and keep at your desk
- Contains all security badge meanings and common scenarios

### Video Tutorials
- **Getting Started** (3 minutes): Basic overview and first use
- **Security Indicators** (2 minutes): Understanding badges and warnings
- **Advanced Features** (5 minutes): Policy settings and troubleshooting
- **Best Practices** (4 minutes): Security tips and recommendations

### Interactive Training
- **Online Module**: Complete 15-minute interactive training
- **Knowledge Check**: Test your understanding
- **Certification**: Required for handling classified information
- **Refresher Training**: Annual updates on new features

### Additional Resources

**Documentation**:
- [Complete User Guide](./user-guide.md) - Detailed feature explanations
- [Policy Guide](./policy-guide.md) - Company-specific encryption policies
- [Troubleshooting Guide](./troubleshooting-guide.md) - Detailed problem resolution

**Security Information**:
- [Understanding Post-Quantum Cryptography](./pqc-explained.md)
- [Company Encryption Policies](./encryption-policies.md)
- [Compliance Requirements](./compliance-guide.md)

**Support Channels**:
- **User Forum**: Internal discussion and tips sharing
- **Monthly Office Hours**: Live Q&A with security team
- **Newsletter**: Updates on new features and threats

## Glossary

**Post-Quantum Cryptography (PQC)**: Encryption methods designed to resist attacks from quantum computers

**Hybrid Mode**: Using both traditional and post-quantum encryption for maximum protection

**ML-KEM-768**: NIST-standardized quantum-resistant key encapsulation mechanism

**ML-DSA-65**: NIST-standardized quantum-resistant digital signature algorithm

**Security Badge**: Visual indicator showing the encryption protection level

**Certificate**: Digital credentials that enable secure communication

**Quantum-Safe**: Protected against both classical and quantum computer attacks

## Contact Information

**General Support**: pqc-support@company.com  
**Security Team**: security@company.com  
**Training**: training@company.com  
**Feedback**: pqc-feedback@company.com  

**Emergency Security Hotline**: +1-555-SECURE-1  
**24/7 IT Support**: +1-555-IT-HELP  

---

*Thank you for helping protect our company's sensitive information with quantum-safe email encryption. For more detailed information, please refer to the complete User Guide.*