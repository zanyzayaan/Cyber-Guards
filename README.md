# Cyber-Guards

Cyber-Guards is a smart cybersecurity web application designed to help users identify and avoid cyber threats such as phishing links, fraudulent messages, malicious emails, and suspicious files.

The platform scans user-provided inputs and generates an intelligent risk score to indicate potential cyber fraud, helping users make safer digital decisions.

## Problem Statement
With the rapid growth of digital communication, cybercrimes such as phishing, online scams, and malicious links are increasing at an alarming rate. Many users lack awareness and technical knowledge to verify suspicious URLs, emails, or messages, leading to data breaches and financial losses. Existing security tools are often complex, paid, or not beginner-friendly.

## Our Solution
Cyber-Guards provides a simple, accessible, and intelligent platform that:
- Scans links, messages, and emails for malicious behavior
- Detects phishing and fraud patterns
- Predicts the risk level of suspicious inputs
- Guides users with clear safety recommendations

## Core Features
- Link / Message / Email Scanner**  
  Paste any URL, message, or email content to analyze potential fraud or malware risk.

- AI-based Vulnerability Scoring**  
  Generates a numerical risk score (0–100) based on domain reputation, keywords, metadata, and detected patterns.

- Risk Analysis Engine**  
  Uses machine learning models, heuristics, and blacklist verification to identify suspicious or malicious behavior.

- User Guidance & Recommendations**  
  Provides actionable suggestions such as *Do not click*, *Suspicious sender*, or *Verified link*.

- **Dashboard**  
  Displays scan history, previous risk scores, and cyber safety tips for users.

## Methodology & Implementation
1. Data Input**  
   Accepts user inputs such as links, emails, messages, or APK files for scanning.

2. Pre-processing**  
   Extracts critical features including domain information, keywords, and metadata.

3. Risk Analysis Engine**  
   Performs intelligent threat detection using ML models, heuristics, and blacklist checks.

4. Vulnerability Score Generation**  
   Calculates a risk score (0–100) to quantify threat severity.

5. Output & Recommendations**  
   Displays results along with reasons and preventive safety advice.

6. Data Storage & Logging**  
   Stores scan results and user activity for analytics, history tracking, and future model improvement.

## User Flow
1. User enters a link, message, or email for analysis  
2. System cleans and extracts relevant features  
3. ML models and blacklist checks analyze the input  
4. A risk score is generated  
5. Results are displayed with safety tips and preventive suggestions

## Tech Stack (Used and To Be Used)
- Frontend: HTML, CSS, Javascript
- Backend: Node.js, Express.js
- Machine Learning: NLTK, spaCy
- API Integrated: Google Safe Browsing
- Security: URL analysis, keyword detection, blacklist verification

## Contribution
This project was developed as a collaborative cybersecurity application.  
This fork reflects my individual contributions, enhancements, and further development to the project.

## Future Scope
- Browser extension for real-time threat detection  
- Suspicious link reporting system  
- Email alert and notification system  

## Disclaimer
This project is developed for educational and learning purposes only.
