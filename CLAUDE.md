# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 🏗️ High-Level Architecture Overview

This repository is a collection of **DevOps tooling and infrastructure setup scripts** primarily focused on containerization (Docker/Podman) and CI/CD pipelines. The architecture is modular, separating concerns into distinct functional areas:

1.  **`build/`**: Contains core scripts for orchestrating the build process (e.g., `universal-ci.sh` for full CI runs, `go-dependencies.sh` for managing language-specific dependencies). These scripts manage the lifecycle of the build artifacts.
2.  **`docker/`**: Holds utility scripts for provisioning and hardening container environments. This includes installing major tools (`aws-cli.sh`, `kubectl-install.sh`) and applying security baselines (`docker-hardening-oscap.sh`).
3.  **`prebuildfs/`**: This directory acts as a library of reusable, isolated filesystem utilities and hooks that can be incorporated directly into a container image's filesystem. These scripts (e.g., `libentrypoint.sh`, `libnet.sh`) provide atomic functions for tasks like service management, network setup, and logging within a container context.

The overall system flow suggests that new features or changes must account for cross-cutting concerns: **security hardening**, **container runtime lifecycle**, and **CI/CD automation**.

## 🛠️ Common Development Commands

### 🚀 Build & CI/CD
*   **Full CI Pipeline:** Run the universal CI script for a complete build and push cycle:
    `./build/universal-ci.sh [image_name] [options]`
*   **Dependency Management (Go):** To ensure a clean environment for Go dependencies:
    `./build/go-dependencies.sh [version]`

### 🐳 Container Setup & Provisioning
*   **Apply Security Hardening:** Always run this script when hardening an image baseline:
    `./docker/docker-hardening-oscap.sh`
*   **Install Key Tools:** Use specific scripts for dependency installation, such as `kubectl-install.sh` or `aws-cli.sh`.

### 🧪 Testing / Validation
*   Since the repository is primarily a collection of build/infra scripts, testing usually means validating script execution or integrating new functionality into a pipeline.
*   **To Test a Utility:** Run the relevant script with `--dry-run` flags if available, or manually step through the logic using basic execution (e.g., `./docker/supercronic-install.sh --dry-run`).
*   **To Test a Feature:** Incorporate the required checks into a temporary CI job or a dedicated integration test script within `build/`.

# SKILLS.md

This document outlines the key software engineering skills and practices I use to write clean, maintainable code that communicates clearly without heavy reliance on inline developer comments. The goal is to make the code itself the primary source of truth—expressive, structured, and easy to understand—while using comments only when they add essential context that can’t be inferred directly.

---

## Core Skills for Writing Self-Documenting Code

### 1. Expressive Naming & Domain-Driven Design
**Skill:** Choosing names that accurately convey purpose, intent, and domain concepts.

- Use descriptive variable, function, class, and module names that tell a story (e.g., `fetch_user_by_id(user_id)` instead of `get(u)`).
- Prefer clarity over brevity: avoid single-letter variables and cryptic abbreviations unless universally understood (e.g., `id`, `url`, `http`).
- Apply domain-driven naming: classes and types should reflect real-world concepts (`Order`, `Invoice`, `PaymentProcessor`) rather than generic utilities (`DataManager`).
- Treat naming as a first-class design activity—renaming is a normal, frequent part of the development workflow.

**Why it matters:** Good names reduce the need for comments and make code readable even when the reader has no prior context.

---

### 2. Small, Single-Purpose Functions (Clean Function Design)
**Skill:** Structuring functions so each one does exactly one thing, with an obvious purpose.

- Keep functions short (often 5–15 lines) and focused on a single task.
- Name functions with a verb + object that describes the action (`calculateMonthlyPayment()` rather than `compute()`).
- Extract intermediate steps into well-named variables or helper functions instead of writing long, multi-step blocks.
- Break complex workflows into a sequence of small, testable functions (e.g., `validateOrder()`, `calculateTax()`, `applyDiscounts()`, `createInvoice()`).

**Why it matters:** Small functions are easier to name, easier to test, and easier to understand without inline explanations.

---

### 3. Clear Structure, Consistent Style, and Readable Control Flow
**Skill:** Organizing code for readability, predictability, and reduced cognitive load.

- Use consistent indentation, formatting, and style (via linters and formatters) to make code visually predictable.
- Group related logic into modules, classes, or files so readers don’t need to assemble scattered pieces.
- Simplify control flow by returning early for invalid conditions and keeping the “happy path” at the top level.
- Avoid clever or compressed expressions; prefer explicit steps that clearly show intent.
- Use constants, enums, or typed values to replace magic numbers and ambiguous flags (e.g., `MAX_LOGIN_ATTEMPTS = 5` instead of scattered `5`s).

**Why it matters:** Structure reduces the mental effort required to understand what the code is doing, which reduces the need for comments.

---

### 4. Intent-Driven Logic & Explicit Intermediate Values
**Skill:** Making the *reason* for code behavior clear through structure and naming, not comments.

- Introduce descriptive intermediate variables to capture conditions and steps (e.g., `isEligibleForDiscount = order.total > 100`).
- Make choices explicit using constants, enums, and well-typed values rather than hardcoded numbers or strings.
- Avoid “clever” tricks (complex one-liners, obscure bit manipulation) unless they are standard and necessary.

**Why it matters:** When intent is explicit, the code becomes its own explanation, reducing the need for “what is this doing?” comments.

---

### 5. Testing as Living Documentation
**Skill:** Using automated tests to communicate usage, expected behavior, and edge cases.

- Write tests that serve as examples of how a function or module should be used.
- Use clear, descriptive test names that read like sentences (e.g., `test_calculate_tax_for_order_above_threshold()`).
- Keep tests simple and focused on observable behavior; they should reinforce correct usage rather than obscure it.

**Why it matters:** Tests provide practical examples and expectations that often convey more than comments, especially for complex logic and APIs.

---

### 6. Strategic Use of Comments (When They Truly Add Value)
**Skill:** Knowing when comments are necessary and writing them to explain *why*, not *what*.

- Use comments to explain **reasons** (trade-offs, business rules, external constraints) that can’t be inferred from the code.
- Document **complex algorithms** briefly when the logic is genuinely non-obvious (and treat that as a signal to refactor if possible).
- Provide **API documentation** (inputs, outputs, edge cases) via docstrings or formal documentation for public interfaces.
- Explain **workarounds** (library bugs, temporary constraints) and the reasoning behind them.
- Avoid restating the code (e.g., `// Increment counter by 1` next to `counter++`)—that’s noise.

**Why it matters:** Comments should be a last resort for clarity, not the default way to explain code.

---

### 7. Continuous Refactoring & Code Review Discipline
**Skill:** Treating code clarity as an ongoing process, not a one-time effort.

- Refactor regularly: rename things, extract functions, simplify logic, and adjust structure as requirements change.
- Use code review feedback to identify confusing areas and improve naming, structure, and test coverage.
- Treat “I need a comment here” as a prompt to improve the code first.

**Why it matters:** Code clarity is a habit that compounds over time, reducing long-term maintenance costs and making teams more productive.

---

## Summary
My approach to clean code focuses on **expressive naming**, **small single-purpose functions**, **clear structure**, **explicit intent**, and **tests as documentation**, with comments reserved for genuinely non-obvious context. This mindset leads to code that’s easier to read, easier to test, and easier to maintain—often without needing developer comments to understand it.

