# Pull Request

## Description
<!-- Describe the changes you've made -->

## Type of change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Security Checklist
- [ ] I have reviewed the code for potential security vulnerabilities
- [ ] Input validation is implemented for all user inputs and external data
- [ ] Error handling is secure and does not reveal sensitive information
- [ ] Docker socket access is properly managed and limited
- [ ] Network requests include proper timeouts and error handling
- [ ] All new code passes the security scans (gosec, govulncheck)

## How Has This Been Tested?
- [ ] Local container build and testing
- [ ] Integration tests with Docker events
- [ ] Security scanning with gosec

## Checklist:
- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] My changes generate no new warnings
- [ ] Any dependent changes have been merged and published