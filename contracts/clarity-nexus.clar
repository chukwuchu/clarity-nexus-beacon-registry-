;; nexus-beacon-registry



;; ========== Error Response Definitions ==========
(define-constant error-void-record (err u401))
(define-constant error-invalid-name (err u403))
(define-constant error-size-overflow (err u404))
(define-constant error-admin-required (err u407))
(define-constant error-restricted-operation (err u408))
(define-constant error-access-forbidden (err u405))
(define-constant error-ownership-mismatch (err u406))
(define-constant error-duplicate-record (err u402))
(define-constant error-metadata-failure (err u409))

;; ========== Administrative Configuration ==========
(define-constant supreme-controller tx-sender)

;; ========== Global State Variables ==========
(define-data-var master-record-counter uint u0)

;; ========== Core Data Storage Structures ==========


(define-map access-permission-grid
  { record-id: uint, granted-user: principal }
  { has-access: bool }
)

(define-map cipher-storage-vault
  { record-id: uint }
  {
    name-hash: (string-ascii 64),
    owner-address: principal,
    data-volume: uint,
    creation-block: uint,
    description-text: (string-ascii 128),
    tag-collection: (list 10 (string-ascii 32))
  }
)

;; ========== Utility Validation Functions ==========

;; Validates that a record exists in the storage vault
(define-private (record-is-present (record-id uint))
  (is-some (map-get? cipher-storage-vault { record-id: record-id }))
)

;; Checks if a single tag meets formatting requirements
(define-private (tag-format-valid (single-tag (string-ascii 32)))
  (and
    (> (len single-tag) u0)
    (< (len single-tag) u33)
  )
)



;; Confirms ownership relationship between user and record
(define-private (confirm-user-ownership (record-id uint) (user-principal principal))
  (match (map-get? cipher-storage-vault { record-id: record-id })
    storage-data (is-eq (get owner-address storage-data) user-principal)
    false
  )
)
