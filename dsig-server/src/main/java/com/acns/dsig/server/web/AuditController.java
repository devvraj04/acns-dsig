package com.acns.dsig.server.web;

import com.acns.dsig.server.persistence.AuditChainService;
import com.acns.dsig.server.persistence.AuditLog;
import com.acns.dsig.server.persistence.AuditLogRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Controller
@RequestMapping("/admin/audit")
public class AuditController {

    private final AuditLogRepository auditLogRepository;
    private final AuditChainService auditChainService;

    public AuditController(AuditLogRepository auditLogRepository, AuditChainService auditChainService) {
        this.auditLogRepository = auditLogRepository;
        this.auditChainService = auditChainService;
    }

    @GetMapping
    public String showAuditLog(Model model) {
        List<AuditLog> entries = auditLogRepository.findAllByOrderBySeqAsc();
        model.addAttribute("entries", entries);
        return "audit";
    }

    @PostMapping("/verify-chain")
    public String verifyChain(Model model) {
        AuditChainService.ChainVerificationResult result = auditChainService.verifyChainIntegrity();
        model.addAttribute("chainResult", result);
        return showAuditLog(model);
    }
}
