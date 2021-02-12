
def register_store_callbacks(ffibuilder):
    # generic destroy func
    ffibuilder.cdef("""
extern "Python" void destroy_func(void *user_data);
    """)

    # identity key store
    ffibuilder.cdef("""
extern "Python" int get_identity_key_pair(signal_buffer **public_data, signal_buffer **private_data, void *user_data);
extern "Python" int get_local_registration_id(uint32_t *registration_id, void *user_data);
extern "Python" int save_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data);
extern "Python" int is_trusted_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data);

typedef struct signal_protocol_identity_key_store {
    /**
     * Get the local client's identity key pair.
     *
     * @param public_data pointer to a newly allocated buffer containing the
     *     public key, if found. Unset if no record was found.
     *     The Signal Protocol library is responsible for freeing this buffer.
     * @param private_data pointer to a newly allocated buffer containing the
     *     private key, if found. Unset if no record was found.
     *     The Signal Protocol library is responsible for freeing this buffer.
     * @return 0 on success, negative on failure
     */
    int (*get_identity_key_pair)(signal_buffer **public_data, signal_buffer **private_data, void *user_data);

    /**
     * Return the local client's registration ID.
     *
     * Clients should maintain a registration ID, a random number
     * between 1 and 16380 that's generated once at install time.
     *
     * @param registration_id pointer to be set to the local client's
     *     registration ID, if it was successfully retrieved.
     * @return 0 on success, negative on failure
     */
    int (*get_local_registration_id)(uint32_t *registration_id, void *user_data);

    /**
     * Save a remote client's identity key
     * <p>
     * Store a remote client's identity key as trusted.
     * The value of key_data may be null. In this case remove the key data
     * from the identity store, but retain any metadata that may be kept
     * alongside it.
     *
     * @param address the address of the remote client
     * @param key_data Pointer to the remote client's identity key, may be null
     * @param key_len Length of the remote client's identity key
     * @return 0 on success, negative on failure
     */
    int (*save_identity)(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data);

    /**
     * Verify a remote client's identity key.
     *
     * Determine whether a remote client's identity is trusted.  Convention is
     * that the TextSecure protocol is 'trust on first use.'  This means that
     * an identity key is considered 'trusted' if there is no entry for the recipient
     * in the local store, or if it matches the saved key for a recipient in the local
     * store.  Only if it mismatches an entry in the local store is it considered
     * 'untrusted.'
     *
     * @param address the address of the remote client
     * @param identityKey The identity key to verify.
     * @param key_data Pointer to the identity key to verify
     * @param key_len Length of the identity key to verify
     * @return 1 if trusted, 0 if untrusted, negative on failure
     */
    int (*is_trusted_identity)(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data);

    /**
     * Function called to perform cleanup when the data store context is being
     * destroyed.
     */
    void (*destroy_func)(void *user_data);

    /** User data pointer */
    void *user_data;
} signal_protocol_identity_key_store;
    """)

    # session store
    ffibuilder.cdef("""
extern "Python" int load_session_func(signal_buffer **record, signal_buffer **user_record, const signal_protocol_address *address, void *user_data);
extern "Python" int get_sub_device_sessions_func(signal_int_list **sessions, const char *name, size_t name_len, void *user_data);
extern "Python" int store_session_func(const signal_protocol_address *address, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data);
extern "Python" int contains_session_func(const signal_protocol_address *address, void *user_data);
extern "Python" int delete_session_func(const signal_protocol_address *address, void *user_data);
extern "Python" int delete_all_sessions_func(const char *name, size_t name_len, void *user_data);

typedef struct signal_protocol_session_store {
    /**
     * Returns a copy of the serialized session record corresponding to the
     * provided recipient ID + device ID tuple.
     *
     * @param record pointer to a freshly allocated buffer containing the
     *     serialized session record. Unset if no record was found.
     *     The Signal Protocol library is responsible for freeing this buffer.
     * @param user_record pointer to a freshly allocated buffer containing
     *     application specific data stored alongside the serialized session
     *     record. If no such data exists, then this pointer may be left unset.
     *     The Signal Protocol library is responsible for freeing this buffer.
     * @param address the address of the remote client
     * @return 1 if the session was loaded, 0 if the session was not found, negative on failure
     */
    int (*load_session_func)(signal_buffer **record, signal_buffer **user_record, const signal_protocol_address *address, void *user_data);

    /**
     * Returns all known devices with active sessions for a recipient
     *
     * @param pointer to an array that will be allocated and populated with the result
     * @param name the name of the remote client
     * @param name_len the length of the name
     * @return size of the sessions array, or negative on failure
     */
    int (*get_sub_device_sessions_func)(signal_int_list **sessions, const char *name, size_t name_len, void *user_data);

    /**
     * Commit to storage the session record for a given
     * recipient ID + device ID tuple.
     *
     * @param address the address of the remote client
     * @param record pointer to a buffer containing the serialized session
     *     record for the remote client
     * @param record_len length of the serialized session record
     * @param user_record pointer to a buffer containing application specific
     *     data to be stored alongside the serialized session record for the
     *     remote client. If no such data exists, then this pointer will be null.
     * @param user_record_len length of the application specific data
     * @return 0 on success, negative on failure
     */
    int (*store_session_func)(const signal_protocol_address *address, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data);

    /**
     * Determine whether there is a committed session record for a
     * recipient ID + device ID tuple.
     *
     * @param address the address of the remote client
     * @return 1 if a session record exists, 0 otherwise.
     */
    int (*contains_session_func)(const signal_protocol_address *address, void *user_data);

    /**
     * Remove a session record for a recipient ID + device ID tuple.
     *
     * @param address the address of the remote client
     * @return 1 if a session was deleted, 0 if a session was not deleted, negative on error
     */
    int (*delete_session_func)(const signal_protocol_address *address, void *user_data);

    /**
     * Remove the session records corresponding to all devices of a recipient ID.
     *
     * @param name the name of the remote client
     * @param name_len the length of the name
     * @return the number of deleted sessions on success, negative on failure
     */
    int (*delete_all_sessions_func)(const char *name, size_t name_len, void *user_data);

    /**
     * Function called to perform cleanup when the data store context is being
     * destroyed.
     */
    void (*destroy_func)(void *user_data);

    /** User data pointer */
    void *user_data;
} signal_protocol_session_store;
    """)

    # pre key store
    ffibuilder.cdef("""
extern "Python" int load_pre_key(signal_buffer **record, uint32_t pre_key_id, void *user_data);
extern "Python" int store_pre_key(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data);
extern "Python" int contains_pre_key(uint32_t pre_key_id, void *user_data);
extern "Python" int remove_pre_key(uint32_t pre_key_id, void *user_data);

typedef struct signal_protocol_pre_key_store {
    /**
     * Load a local serialized PreKey record.
     *
     * @param record pointer to a newly allocated buffer containing the record,
     *     if found. Unset if no record was found.
     *     The Signal Protocol library is responsible for freeing this buffer.
     * @param pre_key_id the ID of the local serialized PreKey record
     * @retval SG_SUCCESS if the key was found
     * @retval SG_ERR_INVALID_KEY_ID if the key could not be found
     */
    int (*load_pre_key)(signal_buffer **record, uint32_t pre_key_id, void *user_data);

    /**
     * Store a local serialized PreKey record.
     *
     * @param pre_key_id the ID of the PreKey record to store.
     * @param record pointer to a buffer containing the serialized record
     * @param record_len length of the serialized record
     * @return 0 on success, negative on failure
     */
    int (*store_pre_key)(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data);

    /**
     * Determine whether there is a committed PreKey record matching the
     * provided ID.
     *
     * @param pre_key_id A PreKey record ID.
     * @return 1 if the store has a record for the PreKey ID, 0 otherwise
     */
    int (*contains_pre_key)(uint32_t pre_key_id, void *user_data);

    /**
     * Delete a PreKey record from local storage.
     *
     * @param pre_key_id The ID of the PreKey record to remove.
     * @return 0 on success, negative on failure
     */
    int (*remove_pre_key)(uint32_t pre_key_id, void *user_data);

    /**
     * Function called to perform cleanup when the data store context is being
     * destroyed.
     */
    void (*destroy_func)(void *user_data);

    /** User data pointer */
    void *user_data;
} signal_protocol_pre_key_store;
    """)

    # signed pre key store
    ffibuilder.cdef("""
extern "Python" int load_signed_pre_key(signal_buffer **record, uint32_t signed_pre_key_id, void *user_data);
extern "Python" int store_signed_pre_key(uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data);
extern "Python" int contains_signed_pre_key(uint32_t signed_pre_key_id, void *user_data);
extern "Python" int remove_signed_pre_key(uint32_t signed_pre_key_id, void *user_data);

typedef struct signal_protocol_signed_pre_key_store {
    /**
     * Load a local serialized signed PreKey record.
     *
     * @param record pointer to a newly allocated buffer containing the record,
     *     if found. Unset if no record was found.
     *     The Signal Protocol library is responsible for freeing this buffer.
     * @param signed_pre_key_id the ID of the local signed PreKey record
     * @retval SG_SUCCESS if the key was found
     * @retval SG_ERR_INVALID_KEY_ID if the key could not be found
     */
    int (*load_signed_pre_key)(signal_buffer **record, uint32_t signed_pre_key_id, void *user_data);

    /**
     * Store a local serialized signed PreKey record.
     *
     * @param signed_pre_key_id the ID of the signed PreKey record to store
     * @param record pointer to a buffer containing the serialized record
     * @param record_len length of the serialized record
     * @return 0 on success, negative on failure
     */
    int (*store_signed_pre_key)(uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data);

    /**
     * Determine whether there is a committed signed PreKey record matching
     * the provided ID.
     *
     * @param signed_pre_key_id A signed PreKey record ID.
     * @return 1 if the store has a record for the signed PreKey ID, 0 otherwise
     */
    int (*contains_signed_pre_key)(uint32_t signed_pre_key_id, void *user_data);

    /**
     * Delete a SignedPreKeyRecord from local storage.
     *
     * @param signed_pre_key_id The ID of the signed PreKey record to remove.
     * @return 0 on success, negative on failure
     */
    int (*remove_signed_pre_key)(uint32_t signed_pre_key_id, void *user_data);

    /**
     * Function called to perform cleanup when the data store context is being
     * destroyed.
     */
    void (*destroy_func)(void *user_data);

    /** User data pointer */
    void *user_data;
} signal_protocol_signed_pre_key_store;
    """)

    # sender key store
    ffibuilder.cdef("""
extern "Python" int store_sender_key(const signal_protocol_sender_key_name *sender_key_name, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data);
extern "Python" int load_sender_key(signal_buffer **record, signal_buffer **user_record, const signal_protocol_sender_key_name *sender_key_name, void *user_data);

typedef struct signal_protocol_sender_key_store {
    /**
     * Store a serialized sender key record for a given
     * (groupId + senderId + deviceId) tuple.
     *
     * @param sender_key_name the (groupId + senderId + deviceId) tuple
     * @param record pointer to a buffer containing the serialized record
     * @param record_len length of the serialized record
     * @param user_record pointer to a buffer containing application specific
     *     data to be stored alongside the serialized record. If no such
     *     data exists, then this pointer will be null.
     * @param user_record_len length of the application specific data
     * @return 0 on success, negative on failure
     */
    int (*store_sender_key)(const signal_protocol_sender_key_name *sender_key_name, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data);

    /**
     * Returns a copy of the sender key record corresponding to the
     * (groupId + senderId + deviceId) tuple.
     *
     * @param record pointer to a newly allocated buffer containing the record,
     *     if found. Unset if no record was found.
     *     The Signal Protocol library is responsible for freeing this buffer.
     * @param user_record pointer to a newly allocated buffer containing
     *     application-specific data stored alongside the record. If no such
     *     data exists, then this pointer may be left unset.
     *     The Signal Protocol library is responsible for freeing this buffer.
     * @param sender_key_name the (groupId + senderId + deviceId) tuple
     * @return 1 if the record was loaded, 0 if the record was not found, negative on failure
     */
    int (*load_sender_key)(signal_buffer **record, signal_buffer **user_record, const signal_protocol_sender_key_name *sender_key_name, void *user_data);

    /**
     * Function called to perform cleanup when the data store context is being
     * destroyed.
     */
    void (*destroy_func)(void *user_data);

    /** User data pointer */
    void *user_data;
} signal_protocol_sender_key_store;
    """)

    ffibuilder.cdef("""
/**
 * Create a new instance of the Signal Protocol data store interface.
 */
int signal_protocol_store_context_create(signal_protocol_store_context **context, signal_context *global_context);

int signal_protocol_store_context_set_session_store(signal_protocol_store_context *context, const signal_protocol_session_store *store);
int signal_protocol_store_context_set_pre_key_store(signal_protocol_store_context *context, const signal_protocol_pre_key_store *store);
int signal_protocol_store_context_set_signed_pre_key_store(signal_protocol_store_context *context, const signal_protocol_signed_pre_key_store *store);
int signal_protocol_store_context_set_identity_key_store(signal_protocol_store_context *context, const signal_protocol_identity_key_store *store);
int signal_protocol_store_context_set_sender_key_store(signal_protocol_store_context *context, const signal_protocol_sender_key_store *store);

void signal_protocol_store_context_destroy(signal_protocol_store_context *context);

/*
 * Interface to the session store.
 * These functions will use the callbacks in the provided
 * signal_protocol_store_context instance and operate in terms of higher level
 * library data structures.
 */

int signal_protocol_session_load_session(signal_protocol_store_context *context, session_record **record, const signal_protocol_address *address);
int signal_protocol_session_get_sub_device_sessions(signal_protocol_store_context *context, signal_int_list **sessions, const char *name, size_t name_len);
int signal_protocol_session_store_session(signal_protocol_store_context *context, const signal_protocol_address *address, session_record *record);
int signal_protocol_session_contains_session(signal_protocol_store_context *context, const signal_protocol_address *address);
int signal_protocol_session_delete_session(signal_protocol_store_context *context, const signal_protocol_address *address);
int signal_protocol_session_delete_all_sessions(signal_protocol_store_context *context, const char *name, size_t name_len);


/*
 * Interface to the pre-key store.
 * These functions will use the callbacks in the provided
 * signal_protocol_store_context instance and operate in terms of higher level
 * library data structures.
 */

int signal_protocol_pre_key_load_key(signal_protocol_store_context *context, session_pre_key **pre_key, uint32_t pre_key_id);
int signal_protocol_pre_key_store_key(signal_protocol_store_context *context, session_pre_key *pre_key);
int signal_protocol_pre_key_contains_key(signal_protocol_store_context *context, uint32_t pre_key_id);
int signal_protocol_pre_key_remove_key(signal_protocol_store_context *context, uint32_t pre_key_id);


/*
 * Interface to the signed pre-key store.
 * These functions will use the callbacks in the provided
 * signal_protocol_store_context instance and operate in terms of higher level
 * library data structures.
 */

int signal_protocol_signed_pre_key_load_key(signal_protocol_store_context *context, session_signed_pre_key **pre_key, uint32_t signed_pre_key_id);
int signal_protocol_signed_pre_key_store_key(signal_protocol_store_context *context, session_signed_pre_key *pre_key);
int signal_protocol_signed_pre_key_contains_key(signal_protocol_store_context *context, uint32_t signed_pre_key_id);
int signal_protocol_signed_pre_key_remove_key(signal_protocol_store_context *context, uint32_t signed_pre_key_id);


/*
 * Interface to the identity key store.
 * These functions will use the callbacks in the provided
 * signal_protocol_store_context instance and operate in terms of higher level
 * library data structures.
 */

int signal_protocol_identity_get_key_pair(signal_protocol_store_context *context, ratchet_identity_key_pair **key_pair);
int signal_protocol_identity_get_local_registration_id(signal_protocol_store_context *context, uint32_t *registration_id);
int signal_protocol_identity_save_identity(signal_protocol_store_context *context, const signal_protocol_address *address, ec_public_key *identity_key);
int signal_protocol_identity_is_trusted_identity(signal_protocol_store_context *context, const signal_protocol_address *address, ec_public_key *identity_key);


/*
 * Interface to the sender key store.
 * These functions will use the callbacks in the provided
 * signal_protocol_store_context instance and operate in terms of higher level
 * library data structures.
 */

int signal_protocol_sender_key_store_key(signal_protocol_store_context *context, const signal_protocol_sender_key_name *sender_key_name, sender_key_record *record);
int signal_protocol_sender_key_load_key(signal_protocol_store_context *context, sender_key_record **record, const signal_protocol_sender_key_name *sender_key_name);
    """)
