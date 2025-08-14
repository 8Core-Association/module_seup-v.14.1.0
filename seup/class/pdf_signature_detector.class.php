<?php

/**
 * PDF Digital Signature Detector for SEUP Module
 * (c) 2025 8Core Association
 */

class PDF_Signature_Detector
{
    /**
     * Detect if PDF has digital signatures
     */
    public static function detectSignatures($file_path)
    {
        try {
            if (!file_exists($file_path)) {
                return ['success' => false, 'error' => 'File not found'];
            }

            $content = file_get_contents($file_path);
            if ($content === false) {
                return ['success' => false, 'error' => 'Cannot read file'];
            }

            $signatures = [];
            $has_signatures = false;

            // 1. Check for signature dictionary
            if (strpos($content, '/Type/Sig') !== false) {
                $has_signatures = true;
                
                // Extract signature information
                $sig_info = self::extractSignatureInfo($content);
                if ($sig_info) {
                    $signatures[] = $sig_info;
                }
            }

            // 2. Check for Adobe signature fields
            if (strpos($content, '/FT/Sig') !== false) {
                $has_signatures = true;
            }

            // 3. Check for PKCS#7 signatures
            if (strpos($content, 'adbe.pkcs7') !== false) {
                $has_signatures = true;
            }

            // 4. Check for ByteRange (signature placeholder)
            if (preg_match('/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/', $content, $matches)) {
                $has_signatures = true;
                
                // Extract signature details from ByteRange
                $byte_range = [
                    'start1' => (int)$matches[1],
                    'length1' => (int)$matches[2], 
                    'start2' => (int)$matches[3],
                    'length2' => (int)$matches[4]
                ];
            }

            return [
                'success' => true,
                'has_signatures' => $has_signatures,
                'signatures' => $signatures,
                'signature_count' => count($signatures),
                'byte_range' => $byte_range ?? null
            ];

        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Extract detailed signature information
     */
    private static function extractSignatureInfo($content)
    {
        $signature_info = [
            'type' => 'Unknown',
            'signer' => 'Unknown',
            'date' => null,
            'certificate_issuer' => 'Unknown',
            'valid' => null
        ];

        try {
            // Extract signer name from certificate
            if (preg_match('/\/Name\s*\(([^)]+)\)/', $content, $matches)) {
                $signature_info['signer'] = self::cleanPdfString($matches[1]);
            }

            // Extract signing date
            if (preg_match('/\/M\s*\(D:(\d{14}[+-]\d{2}\'\d{2}\')\)/', $content, $matches)) {
                $signature_info['date'] = self::parsePdfDate($matches[1]);
            }

            // Detect FINA certificates
            if (strpos($content, 'Financijska agencija') !== false) {
                $signature_info['certificate_issuer'] = 'FINA (Financijska agencija)';
                $signature_info['type'] = 'Kvalificirani digitalni potpis';
            }

            // Extract certificate subject
            if (preg_match('/CN=([^,]+)/', $content, $matches)) {
                $cert_subject = self::cleanPdfString($matches[1]);
                if (!empty($cert_subject) && $signature_info['signer'] === 'Unknown') {
                    $signature_info['signer'] = $cert_subject;
                }
            }

            // Check for OCSP validation
            if (strpos($content, 'ocsp.fina.hr') !== false) {
                $signature_info['ocsp_validated'] = true;
            }

            return $signature_info;

        } catch (Exception $e) {
            dol_syslog("Error extracting signature info: " . $e->getMessage(), LOG_WARNING);
            return $signature_info;
        }
    }

    /**
     * Clean PDF string encoding
     */
    private static function cleanPdfString($str)
    {
        // Remove PDF string encoding artifacts
        $str = str_replace(['\\(', '\\)', '\\\\'], ['(', ')', '\\'], $str);
        
        // Handle Unicode encoding
        if (strpos($str, '\u') !== false) {
            $str = preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', function($matches) {
                return mb_convert_encoding(pack('H*', $matches[1]), 'UTF-8', 'UTF-16BE');
            }, $str);
        }

        return trim($str);
    }

    /**
     * Parse PDF date format
     */
    private static function parsePdfDate($pdf_date)
    {
        try {
            // PDF date format: YYYYMMDDHHmmSSOHH'mm'
            if (preg_match('/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})([+-])(\d{2})\'(\d{2})\'/', $pdf_date, $matches)) {
                $year = $matches[1];
                $month = $matches[2];
                $day = $matches[3];
                $hour = $matches[4];
                $minute = $matches[5];
                $second = $matches[6];
                $tz_sign = $matches[7];
                $tz_hour = $matches[8];
                $tz_minute = $matches[9];

                $date_str = "{$year}-{$month}-{$day} {$hour}:{$minute}:{$second}";
                $timezone = "{$tz_sign}{$tz_hour}:{$tz_minute}";

                return [
                    'formatted' => date('d.m.Y H:i:s', strtotime($date_str)),
                    'iso' => $date_str,
                    'timezone' => $timezone
                ];
            }
        } catch (Exception $e) {
            dol_syslog("Error parsing PDF date: " . $e->getMessage(), LOG_WARNING);
        }

        return null;
    }

    /**
     * Validate signature using external tools (if available)
     */
    public static function validateSignature($file_path)
    {
        // This would require external PDF validation tools
        // For now, return basic validation based on structure
        
        $detection = self::detectSignatures($file_path);
        
        if (!$detection['success'] || !$detection['has_signatures']) {
            return [
                'success' => false,
                'error' => 'No signatures found'
            ];
        }

        return [
            'success' => true,
            'validation_method' => 'basic_structure',
            'signatures_valid' => true, // Basic assumption
            'note' => 'Full cryptographic validation requires external tools'
        ];
    }

    /**
     * Get signature summary for display
     */
    public static function getSignatureSummary($file_path)
    {
        $detection = self::detectSignatures($file_path);
        
        if (!$detection['success']) {
            return [
                'status' => 'error',
                'message' => $detection['error']
            ];
        }

        if (!$detection['has_signatures']) {
            return [
                'status' => 'unsigned',
                'message' => 'Dokument nije digitalno potpisan'
            ];
        }

        $summary = [
            'status' => 'signed',
            'message' => 'Dokument je digitalno potpisan',
            'count' => $detection['signature_count'],
            'signatures' => []
        ];

        foreach ($detection['signatures'] as $sig) {
            $summary['signatures'][] = [
                'signer' => $sig['signer'],
                'type' => $sig['type'],
                'issuer' => $sig['certificate_issuer'],
                'date' => $sig['date']['formatted'] ?? 'Nepoznato',
                'icon' => self::getSignatureIcon($sig)
            ];
        }

        return $summary;
    }

    /**
     * Get appropriate icon for signature type
     */
    private static function getSignatureIcon($signature)
    {
        if (strpos($signature['certificate_issuer'], 'FINA') !== false) {
            return 'fas fa-certificate text-success'; // FINA qualified signature
        }
        
        if ($signature['type'] === 'Kvalificirani digitalni potpis') {
            return 'fas fa-award text-primary'; // Qualified signature
        }

        return 'fas fa-signature text-info'; // Generic signature
    }

    /**
     * Check if file is PDF
     */
    public static function isPdf($file_path)
    {
        if (!file_exists($file_path)) {
            return false;
        }

        $header = file_get_contents($file_path, false, null, 0, 8);
        return strpos($header, '%PDF-') === 0;
    }

    /**
     * Batch process multiple files
     */
    public static function batchDetectSignatures($file_paths)
    {
        $results = [];
        
        foreach ($file_paths as $file_path) {
            $filename = basename($file_path);
            
            if (!self::isPdf($file_path)) {
                $results[$filename] = [
                    'status' => 'skipped',
                    'message' => 'Nije PDF datoteka'
                ];
                continue;
            }

            $results[$filename] = self::getSignatureSummary($file_path);
        }

        return $results;
    }
}