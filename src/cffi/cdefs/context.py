def register_context_callbacks(ffibuilder):
    # random
    ffibuilder.cdef("""
extern "Python" void signal_lock(void *user_data);
extern "Python" void signal_unlock(void *user_data);
extern "Python" void signal_log(int level, const char *message, size_t len, void *user_data);

/**
 * Create a new instance of the global library context.
 */
int signal_context_create(signal_context **context, void *user_data);

/**
 * Set the crypto provider to be used by the Signal Protocol library.
 *
 * @param crypto_provider Populated structure of crypto provider function
 *     pointers. The contents of this structure are copied, so the caller
 *     does not need to maintain its instance.
 * @return 0 on success, negative on failure
 */
int signal_context_set_crypto_provider(signal_context *context, const signal_crypto_provider *crypto_provider);

/**
 * Set the locking functions to be used by the Signal Protocol library for
 * synchronization.
 *
 * Note: These functions must allow recursive locking (e.g. PTHREAD_MUTEX_RECURSIVE)
 *
 * @param lock function to lock a mutex
 * @param unlock function to unlock a mutex
 * @return 0 on success, negative on failure
 */
int signal_context_set_locking_functions(signal_context *context,
        void (*lock)(void *user_data), void (*unlock)(void *user_data));

/**
 * Set the log function to be used by the Signal Protocol library for logging.
 *
 * @return 0 on success, negative on failure
 */
int signal_context_set_log_function(signal_context *context,
        void (*log)(int level, const char *message, size_t len, void *user_data));

void signal_context_destroy(signal_context *context);
    """)
