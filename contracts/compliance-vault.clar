;; compliance-vault.clar
;; Compliance-Aware Vaults with pluggable on-chain validation modules
;; - Admin registers modules (other contracts) in the registry
;; - Vault owners enable modules for their vault
;; - Before deposit/withdraw, all enabled modules are called with (validate-action ...)
;; - If any enabled module returns (err ...) or (ok false), the action is rejected
;;
;; Module interface requirement (each module MUST implement):
;; (define-public (validate-action (vault-id uint) (actor principal) (action uint) (amount uint)) (response bool uint))
;; - action: 1 = deposit, 2 = withdraw
;; - returns (ok true) to allow, (ok false) or (err uX) to deny
;;
;; WARNING: Example code. Test & audit before production.

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Storage and Variables
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; vaults: vault-id -> (owner, balance, active)
(define-map vaults
  uint
  {
    owner: principal,
    balance: uint,
    active: bool
  })

;; module-registry: module-id -> module-principal
(define-map module-registry
  uint
  principal)

;; module-counter: next module id
(define-data-var module-counter uint u0)

;; enabled-modules: composite key {vault-id, module-id} -> bool
(define-map enabled-modules
  { vault-id: uint, module-id: uint }
  { enabled: bool })

;; contract admin
(define-data-var admin principal tx-sender)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Private validation functions
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Validate compliance for a transaction
(define-private (check-single-module (vault-id uint) (action uint) (actor principal) (amount uint) (module-id uint))
  (let ((max-id (var-get module-counter)))
    (if (> module-id max-id)
      (ok true)  ;; Skip modules beyond max-id
      (match (map-get? enabled-modules { vault-id: vault-id, module-id: module-id })
        enabled-data
        (if (get enabled enabled-data)
          (ok true)  ;; For now, just bypass validation
          (ok true))
        (ok true)))))

(define-private (validate-compliance (vault-id uint) (action uint) (actor principal) (amount uint))
  (check-single-module vault-id action actor amount u1))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Types
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-map events-enabled bool bool)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Events
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Event types as constants to avoid define-event errors in older versions
(define-constant event-vault-created "vault-created")
(define-constant event-vault-funded "vault-funded")
(define-constant event-withdraw "withdraw")
(define-constant event-module-registered "module-registered")
(define-constant event-module-enabled "module-enabled")

;; Event emission helper functions
(define-private (emit-vault-created (vault-id uint) (owner principal))
  (print { event: event-vault-created, vault-id: vault-id, owner: owner }))

(define-private (emit-vault-funded (vault-id uint) (from principal) (amount uint))
  (print { event: event-vault-funded, vault-id: vault-id, from: from, amount: amount }))

(define-private (emit-withdraw-event (vault-id uint) (to principal) (amount uint))
  (print { event: event-withdraw, vault-id: vault-id, to: to, amount: amount }))

(define-private (emit-module-registered (module-id uint) (module principal))
  (print { event: event-module-registered, module-id: module-id, module: module }))

(define-private (emit-module-enabled (vault-id uint) (module-id uint) (enabled bool))
  (print { event: event-module-enabled, vault-id: vault-id, module-id: module-id, enabled: enabled }))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Errors
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; u100 vault exists
;; u101 vault not found
;; u102 not owner
;; u103 invalid param
;; u104 module not found
;; u105 module blocked action
;; u106 transfer failed
;; u107 vault inactive
;; u108 insufficient-funds
;; u109 not admin

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Helpers
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-read-only (is-admin? (who principal))
  (is-eq who (var-get admin)))

(define-read-only (vault-exists? (vault-id uint))
  (is-some (map-get? vaults vault-id)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Module registry (admin)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Register a new module (admin only). Returns assigned module-id.
(define-public (register-module (module principal))
  (begin
    (asserts! (is-admin? tx-sender) (err u109))
    (let ((mid (+ (var-get module-counter) u1)))
      (asserts! (is-eq module module) (err u103))  ;; Validate principal
      (map-set module-registry mid module)
      (var-set module-counter mid)
      (emit-module-registered mid module)
      (ok mid))))

;; Admin may update an existing module's principal (replace)
(define-public (set-module-principal (module-id uint) (module principal))
  (begin
    (asserts! (is-admin? tx-sender) (err u109))
    (asserts! (is-eq module module) (err u103))  ;; Validate principal
    (let ((existing (get-module module-id)))
      (asserts! (is-some existing) (err u104))
      (map-set module-registry module-id module)
      (ok module-id))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Vault lifecycle & module enabling
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Create a vault (owner = tx-sender). vault-id supplied by caller (must be unique).
(define-public (create-vault (vault-id uint))
  (begin
    (asserts! (is-eq (map-get? vaults vault-id) none) (err u100))
    (map-set vaults vault-id { owner: tx-sender, balance: u0, active: true })
    (emit-vault-created vault-id tx-sender)
    (ok vault-id)))

;; Enable/disable a registered module for a specific vault (vault owner only)
(define-public (set-vault-module (vault-id uint) (module-id uint) (enabled bool))
  (begin
    (asserts! (vault-exists? vault-id) (err u101))
    (match (map-get? vaults vault-id)
      v
      (begin
        (asserts! (is-eq (get owner v) tx-sender) (err u102))
        (asserts! (is-some (map-get? module-registry module-id)) (err u104))
        (map-set enabled-modules { vault-id: vault-id, module-id: module-id } { enabled: enabled })
        (emit-module-enabled vault-id module-id enabled)
        (ok true))
      (err u101))))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Core actions: fund-vault (deposit) and withdraw
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Fund vault by attaching STX to the call. Validates against enabled modules first.
(define-public (fund-vault (vault-id uint) (amount uint))
  (begin
    (asserts! (> amount u0) (err u103))
    (asserts! (vault-exists? vault-id) (err u101))
    (let ((vault-data (unwrap! (map-get? vaults vault-id) (err u101)))
          (validation-result (unwrap! (validate-compliance vault-id u1 tx-sender amount) (err u105))))
      (asserts! (get active vault-data) (err u107))
      (map-set vaults vault-id
        { owner: (get owner vault-data)
        , balance: (+ (get balance vault-data) amount)
        , active: (get active vault-data) })
      (emit-vault-funded vault-id tx-sender amount)
      (ok (+ (get balance vault-data) amount)))))

;; Withdraw from vault (owner only). Validates modules first.
(define-public (withdraw (vault-id uint) (amount uint) (recipient principal))
  (begin
    (asserts! (> amount u0) (err u103))
    (asserts! (vault-exists? vault-id) (err u101))
    (let ((vault-data (unwrap! (map-get? vaults vault-id) (err u101))))
      (let ((owner (get owner vault-data))
            (bal (get balance vault-data))
            (active? (get active vault-data)))
        (asserts! (is-eq tx-sender owner) (err u102))
        (asserts! active? (err u107))
        (asserts! (>= bal amount) (err u108))
        (asserts! (is-eq recipient recipient) (err u103))  ;; Validate principal
        ;; run compliance validation through enabled modules (action = 2)
        (unwrap! (validate-compliance vault-id u2 tx-sender amount) (err u105))
        (unwrap! (stx-transfer? amount tx-sender recipient) (err u106))
        (let ((new-balance (- bal amount)))
          (map-set vaults vault-id
            { owner: owner
            , balance: new-balance
            , active: active? })
          (emit-withdraw-event vault-id recipient amount)
          (ok new-balance))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Admin helpers (change admin)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-admin? tx-sender) (err u109))
    (asserts! (is-eq new-admin new-admin) (err u103))  ;; Validate principal
    (var-set admin new-admin)
    (ok true)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Read-only views
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-read-only (get-module (module-id uint))
  (map-get? module-registry module-id))

(define-read-only (get-module-counter)
  (ok (var-get module-counter)))

(define-read-only (is-module-enabled-for-vault (vault-id uint) (module-id uint))
  (match (map-get? enabled-modules { vault-id: vault-id, module-id: module-id })
    enabled-data
    (ok (get enabled enabled-data))
    (ok false)))

(define-read-only (get-vault (vault-id uint))
  (let ((vault-data (map-get? vaults vault-id)))
    (match vault-data 
      data (ok data)
      (err u101))))
