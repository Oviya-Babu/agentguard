"""
Advanced mTLS Hardening
=======================

Enhanced certificate validation:
- Certificate chain depth
- Key usage constraints
- Expiration window checking
- Fingerprint pinning (optional)
- Subject/Issuer validation
"""

import hashlib
import re
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class AdvancedmTLSValidator:
    """
    Enterprise-grade mTLS certificate validation.
    """
    
    def __init__(
        self,
        expected_service_identity: str = "agentguard-triage",
        verify_chain_depth: bool = True,
        verify_key_usage: bool = True,
        min_days_until_expiry: int = 7,  # Warn if expires within 7 days
        max_chain_depth: int = 3,
        pinned_fingerprints: Optional[list] = None,
    ):
        self.expected_service_identity = expected_service_identity
        self.verify_chain_depth = verify_chain_depth
        self.verify_key_usage = verify_key_usage
        self.min_days_until_expiry = min_days_until_expiry
        self.max_chain_depth = max_chain_depth
        self.pinned_fingerprints = pinned_fingerprints or []
    
    def extract_cn(self, subject_dict: Dict) -> Optional[str]:
        """Extract CN from certificate subject."""
        for rdn in subject_dict.get("RDNSequence", []):
            for name_type_and_value in rdn:
                oid = name_type_and_value[0]
                if str(oid) == "2.5.4.3":  # CN OID
                    return str(name_type_and_value[1])
        return None
    
    def extract_san(self, extensions: list) -> Optional[str]:
        """Extract Subject Alternative Name."""
        for ext in extensions:
            oid = ext.get("extn_id", "")
            if str(oid) == "2.5.29.17":  # SAN OID
                critical = ext.get("critical", False)
                try:
                    san_value = ext.get("extn_value", {})
                    # Parse SAN (simplified for DNS names)
                    if isinstance(san_value, dict):
                        for dns_name in san_value.get("dNSName", []):
                            return str(dns_name)
                except Exception:
                    pass
        return None
    
    def validate_cn(self, cn: Optional[str]) -> bool:
        """Validate CN matches expected service identity."""
        if not cn:
            return False
        return cn == self.expected_service_identity
    
    def validate_san(self, san: Optional[str]) -> bool:
        """Validate SAN matches expected service identity."""
        if not san:
            return False
        # Support wildcard matching if needed
        if san.startswith("*."):
            pattern = san.replace("*.", ".*\\.").replace(".", "\\.")
            return bool(re.match(pattern, self.expected_service_identity))
        return san == self.expected_service_identity
    
    def validate_expiration(self, not_after: Optional[str]) -> Tuple[bool, Optional[str]]:
        """
        Validate certificate expiration.
        
        Returns: (is_valid, warning_message)
        """
        if not not_after:
            return False, "Missing expiration date"
        
        try:
            # Parse ISO 8601 format
            exp_date = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
            now = datetime.now(exp_date.tzinfo) if exp_date.tzinfo else datetime.utcnow()
            
            # Check if expired
            if exp_date <= now:
                return False, "Certificate expired"
            
            # Check if expires soon
            expiry_warning = now + timedelta(days=self.min_days_until_expiry)
            if exp_date <= expiry_warning:
                days_left = (exp_date - now).days
                return True, f"Certificate expires in {days_left} days (warning)"
            
            return True, None
        except Exception as e:
            return False, f"Failed to parse expiration: {str(e)}"
    
    def validate_key_usage(self, extensions: list) -> Tuple[bool, Optional[str]]:
        """
        Validate Key Usage extension.
        
        For client certificates, must have digitalSignature and keyAgreement.
        """
        if not self.verify_key_usage:
            return True, None
        
        for ext in extensions:
            oid = ext.get("extn_id", "")
            if str(oid) == "2.5.29.15":  # Key Usage OID
                try:
                    key_usage = ext.get("extn_value", {})
                    # Check for required bits
                    digital_sig = key_usage.get("digitalSignature", False)
                    key_agreement = key_usage.get("keyAgreement", False) or \
                                   key_usage.get("keyEncipherment", False)
                    
                    if not (digital_sig and key_agreement):
                        return False, "Missing required key usage bits"
                    
                    return True, None
                except Exception as e:
                    return False, f"Failed to parse key usage: {str(e)}"
        
        # Key Usage extension not found (warning)
        return True, "Key Usage extension not found"
    
    def validate_chain_depth(self, cert_dict: Dict) -> Tuple[bool, Optional[str]]:
        """
        Validate certificate chain depth.
        
        Prevents excessively long chains that could hide issues.
        """
        if not self.verify_chain_depth:
            return True, None
        
        try:
            # In a real scenario, this would traverse the chain
            # For now, check BasicConstraints pathLenConstraint
            extensions = cert_dict.get("extensions", [])
            
            for ext in extensions:
                oid = ext.get("extn_id", "")
                if str(oid) == "2.5.29.19":  # Basic Constraints OID
                    constraint = ext.get("extn_value", {})
                    path_len = constraint.get("pathLenConstraint", 999)
                    
                    if path_len > self.max_chain_depth:
                        return False, f"Chain depth too deep ({path_len} > {self.max_chain_depth})"
            
            return True, None
        except Exception as e:
            return False, f"Failed to validate chain: {str(e)}"
    
    def validate_fingerprint(self, cert_der: bytes) -> Tuple[bool, Optional[str]]:
        """
        Validate certificate fingerprint against pinned list.
        """
        if not self.pinned_fingerprints:
            return True, None  # Pinning disabled
        
        try:
            # SHA256 fingerprint
            fingerprint = hashlib.sha256(cert_der).hexdigest()
            
            if fingerprint not in self.pinned_fingerprints:
                return False, "Certificate fingerprint not pinned"
            
            return True, None
        except Exception as e:
            return False, f"Failed to validate fingerprint: {str(e)}"
    
    def validate_certificate(self, cert_dict: Dict, cert_der: Optional[bytes] = None) -> Tuple[bool, list]:
        """
        Comprehensive certificate validation.
        
        Returns: (is_valid, list_of_warnings)
        """
        warnings = []
        
        # Extract certificate fields
        subject = cert_dict.get("subject", {})
        extensions = cert_dict.get("extensions", [])
        not_after = cert_dict.get("not_after")
        
        cn = self.extract_cn(subject)
        san = self.extract_san(extensions)
        
        # Validate CN
        if not self.validate_cn(cn):
            return False, ["CN does not match expected service identity"]
        
        # Validate SAN
        if san and not self.validate_san(san):
            return False, ["SAN does not match expected service identity"]
        
        # Validate expiration
        exp_valid, exp_warning = self.validate_expiration(not_after)
        if not exp_valid:
            return False, [exp_warning]
        if exp_warning:
            warnings.append(exp_warning)
        
        # Validate key usage
        key_valid, key_warning = self.validate_key_usage(extensions)
        if not key_valid:
            return False, [key_warning]
        if key_warning:
            warnings.append(key_warning)
        
        # Validate chain depth
        chain_valid, chain_warning = self.validate_chain_depth(cert_dict)
        if not chain_valid:
            return False, [chain_warning]
        if chain_warning:
            warnings.append(chain_warning)
        
        # Validate fingerprint (if pinning enabled)
        if cert_der:
            fp_valid, fp_warning = self.validate_fingerprint(cert_der)
            if not fp_valid:
                return False, [fp_warning]
            if fp_warning:
                warnings.append(fp_warning)
        
        return True, warnings


# Global validator instance
advanced_mtls_validator = AdvancedmTLSValidator()
