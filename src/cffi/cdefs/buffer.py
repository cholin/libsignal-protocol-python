def register_buffer(ffibuilder):
    ffibuilder.cdef("""
/**
 * Allocate a new buffer to store data of the provided length.
 *
 * @param len length of the buffer to allocate
 * @return pointer to the allocated buffer, or 0 on failure
 */
signal_buffer *signal_buffer_alloc(size_t len);

/**
 * Create a new buffer and copy the provided data into it.
 *
 * @param data pointer to the start of the data
 * @param len length of the data
 * @return pointer to the allocated buffer, or 0 on failure
 */
signal_buffer *signal_buffer_create(const uint8_t *data, size_t len);

/**
 * Create a copy of an existing buffer.
 *
 * @param buffer the existing buffer to copy
 * @return pointer to the updated buffer, or 0 on failure
 */
signal_buffer *signal_buffer_copy(const signal_buffer *buffer);

/**
 * Create a copy of an existing buffer.
 *
 * @param buffer the existing buffer to copy
 * @param n the maximum number of bytes to copy
 * @return pointer to the updated buffer, or 0 on failure
 */
signal_buffer *signal_buffer_n_copy(const signal_buffer *buffer, size_t n);

/**
 * Append the provided data to an existing buffer.
 * Note: The underlying buffer is only expanded by an amount sufficient
 * to hold the data being appended. There is no additional reserved space
 * to reduce the need for memory allocations.
 *
 * @param buffer the existing buffer to append to
 * @param data pointer to the start of the data
 * @param len length of the data
 * @return pointer to the updated buffer, or 0 on failure
 */
signal_buffer *signal_buffer_append(signal_buffer *buffer, const uint8_t *data, size_t len);

/**
 * Gets the data pointer for the buffer.
 * This can be used to read and write data stored in the buffer.
 *
 * @param buffer pointer to the buffer instance
 * @return data pointer
 */
uint8_t *signal_buffer_data(signal_buffer *buffer);

/**
 * Gets the data pointer for the buffer.
 * This can be used to read and write data stored in the buffer.
 *
 * @param buffer pointer to the buffer instance
 * @return data pointer
 */
const uint8_t *signal_buffer_const_data(const signal_buffer *buffer);

/**
 * Gets the length of the data stored within the buffer.
 *
 * @param buffer pointer to the buffer instance
 * @return data length
 */
size_t signal_buffer_len(const signal_buffer *buffer);

/**
 * Compare two buffers.
 *
 * @param buffer1 first buffer to compare
 * @param buffer2 second buffer to compare
 * @return 0 if the two buffers are equal, negative or positive otherwise
 */
int signal_buffer_compare(signal_buffer *buffer1, signal_buffer *buffer2);

/**
 * Free the data buffer.
 *
 * @param buffer pointer to the buffer instance to free
 */
void signal_buffer_free(signal_buffer *buffer);

/**
 * Zero and free the data buffer.
 * This function should be used when the buffer contains sensitive
 * data, to make sure the memory is cleared before being freed.
 *
 * @param buffer pointer to the buffer instance to free
 */
void signal_buffer_bzero_free(signal_buffer *buffer);
    """)
