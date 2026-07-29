"""A richer, realistic technique/statement corpus for Task 5's labelled
retrieval eval set — real ATT&CK/ATLAS technique names and paraphrased
public descriptions, large enough to give recall@k assertions actual
signal (unlike Task 3's minimal 3-technique golden fixtures)."""

from app.services.cri.models import DiagnosticStatement
from app.services.kb.models import TechniqueChunk


def sample_technique_chunks() -> list[TechniqueChunk]:
    def enterprise(id_, name, description, tactics, platforms=("Linux", "Windows", "macOS")):
        return TechniqueChunk(
            id=id_,
            matrix="enterprise",
            name=name,
            tactics=tactics,
            description=description,
            detection="",
            platforms=platforms,
            data_sources=(),
        )

    def atlas(id_, name, description, tactics):
        return TechniqueChunk(
            id=id_,
            matrix="atlas",
            name=name,
            tactics=tactics,
            description=description,
            detection="",
            platforms=(),
            data_sources=(),
        )

    return [
        enterprise(
            "T1190",
            "Exploit Public-Facing Application",
            "Adversaries may attempt to exploit a weakness in an Internet-facing host or "
            "system to initially access a network, using software bugs, misconfigurations, "
            "or vulnerabilities in web servers and applications.",
            ("initial-access",),
        ),
        enterprise(
            "T1566",
            "Phishing",
            "Adversaries may send phishing messages to gain access to victim systems, "
            "using spearphishing attachments or links to deliver malicious payloads.",
            ("initial-access",),
        ),
        enterprise(
            "T1059",
            "Command and Scripting Interpreter",
            "Adversaries may abuse command and script interpreters to execute commands, "
            "scripts, or binaries, including PowerShell, Unix shells, or Python.",
            ("execution",),
        ),
        enterprise(
            "T1547",
            "Boot or Logon Autostart Execution",
            "Adversaries may configure system settings to automatically execute a program "
            "during system boot or logon to maintain persistence.",
            ("persistence", "privilege-escalation"),
        ),
        enterprise(
            "T1548",
            "Abuse Elevation Control Mechanism",
            "Adversaries may circumvent mechanisms designed to control elevated privileges "
            "to gain higher-level permissions on a system.",
            ("privilege-escalation", "defense-evasion"),
        ),
        enterprise(
            "T1027",
            "Obfuscated Files or Information",
            "Adversaries may attempt to make an executable or file difficult to discover "
            "or analyze by encrypting, encoding, or otherwise obfuscating its contents.",
            ("defense-evasion",),
        ),
        enterprise(
            "T1110",
            "Brute Force",
            "Adversaries may use brute force techniques to gain access to accounts when "
            "passwords are unknown, including password guessing and credential stuffing.",
            ("credential-access",),
        ),
        enterprise(
            "T1003",
            "OS Credential Dumping",
            "Adversaries may attempt to dump credentials to obtain account login and "
            "password information from the operating system.",
            ("credential-access",),
        ),
        enterprise(
            "T1082",
            "System Information Discovery",
            "Adversaries may attempt to get detailed information about the operating "
            "system and hardware of a victim system.",
            ("discovery",),
        ),
        enterprise(
            "T1021",
            "Remote Services",
            "Adversaries may use valid accounts to log into remote services such as RDP "
            "or SSH to move laterally within a network.",
            ("lateral-movement",),
        ),
        enterprise(
            "T1560",
            "Archive Collected Data",
            "Adversaries may compress or encrypt collected data prior to exfiltration to "
            "minimize the amount of data sent over the network.",
            ("collection",),
        ),
        enterprise(
            "T1071",
            "Application Layer Protocol",
            "Adversaries may communicate using OSI application layer protocols such as "
            "HTTP or DNS to avoid detection by blending in with existing traffic.",
            ("command-and-control",),
        ),
        enterprise(
            "T1041",
            "Exfiltration Over C2 Channel",
            "Adversaries may steal data by exfiltrating it over an existing command and "
            "control channel rather than a separate exfiltration channel.",
            ("exfiltration",),
        ),
        enterprise(
            "T1486",
            "Data Encrypted for Impact",
            "Adversaries may encrypt data on target systems to interrupt availability, "
            "commonly deployed as ransomware to extort victim organizations.",
            ("impact",),
        ),
        atlas(
            "AML.T0043",
            "Craft Adversarial Data",
            "Adversaries may craft adversarial data — inputs designed to cause an AI model "
            "to misclassify or produce an incorrect output — to evade or manipulate a "
            "target machine learning system.",
            ("ai-model-access",),
        ),
        atlas(
            "AML.T0020",
            "Poison Training Data",
            "Adversaries may attempt to poison datasets used to train a victim's AI model "
            "by injecting malicious samples into the training data pipeline.",
            ("resource-development",),
        ),
        atlas(
            "AML.T0024",
            "Exfiltration via ML Inference API",
            "Adversaries may repeatedly query a hosted machine learning inference "
            "endpoint to reconstruct or steal the underlying model or its training data.",
            ("exfiltration",),
        ),
        atlas(
            "AML.T0018",
            "Backdoor ML Model",
            "Adversaries may introduce a backdoor into a machine learning model during "
            "training so that a specific trigger input causes a chosen misbehavior.",
            ("persistence",),
        ),
    ]


def sample_diagnostic_statements() -> list[DiagnosticStatement]:
    def statement(profile_id, csf_path, name, text, tiers, tags=()):
        return DiagnosticStatement(
            outline_id=profile_id,
            profile_id=profile_id,
            csf_path=csf_path,
            name=name,
            text=text,
            applicable_tiers=tiers,
            subject_tags=tags,
        )

    return [
        statement(
            "GV.OC-01.01",
            ("GOVERN", "Organizational Context", "Organizational Mission"),
            "Governance alignment",
            "Technology and cybersecurity strategies are formally governed to align with "
            "the organization's mission, objectives, and risk profile.",
            (1, 2, 3, 4),
            ("#mission_and_strategy", "#risk_management"),
        ),
        statement(
            "PR.AA-05.01",
            ("PROTECT", "Identity Management, Authentication, and Access Control", "Access Authorizations"),
            "Privileged access control",
            "The organization institutes controls over privileged system access by "
            "strictly limiting and closely managing staff with elevated entitlements, "
            "including multi-factor authentication.",
            (1, 2, 3),
            ("#access_management", "#authentication"),
        ),
        statement(
            "DE.CM-01.03",
            ("DETECT", "Continuous Monitoring", "Network Monitoring"),
            "Network traffic monitoring",
            "The organization monitors network traffic for anomalous patterns that may "
            "indicate command and control or exfiltration activity.",
            (1, 2),
            ("#network_monitoring", "#detection"),
        ),
        statement(
            "RC.RP-01.02",
            ("RECOVER", "Recovery Planning", "Backup Restoration"),
            "Backup restoration testing",
            "The organization periodically tests the restoration of backups to verify "
            "recovery time objectives can be met after a disruptive event.",
            (1, 2, 3, 4),
            ("#backup_and_recovery",),
        ),
    ]
