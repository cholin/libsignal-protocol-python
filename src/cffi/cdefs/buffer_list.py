def register_buffer_list(ffibuilder):
    ffibuilder.cdef("""
/**
 * Allocate a new buffer list.
 *
 * @return pointer to the allocated buffer, or 0 on failure
 */
signal_buffer_list *signal_buffer_list_alloc(void);

/**
 * Create a copy of an existing buffer list.
 *
 * @param list the existing buffer list to copy
 * @return pointer to the updated buffer, or 0 on failure
 */
signal_buffer_list *signal_buffer_list_copy(const signal_buffer_list *list);

/**
 * Push the provided buffer onto the end of the list.
 * The list will take ownership of the buffer, and free it when the list is
 * freed.
 *
 * @param list the buffer list
 * @param buffer the buffer to push
 * @return 0 on success, or negative on failure
 */
int signal_buffer_list_push_back(signal_buffer_list *list, signal_buffer *buffer);

/**
 * Gets the size of the buffer list.
 *
 * @param list the buffer list
 * @return the size of the list
 */
unsigned int signal_buffer_list_size(signal_buffer_list *list);

/**
 * Gets the value of the element at a particular index in the list
 *
 * @param list the list
 * @param index the index within the list
 * @return the value
 */
signal_buffer *signal_buffer_list_at(signal_buffer_list *list, unsigned int index);

/**
 * Free the buffer list, including all the buffers added to it.
 *
 * @param list the buffer list
 */
void signal_buffer_list_free(signal_buffer_list *list);

/**
 * Free the buffer list, including all the buffers added to it.
 * This function should be used when the buffer list contains sensitive
 * data, to make sure the memory is cleared before being freed.
 *
 * @param list the buffer list
 */
void signal_buffer_list_bzero_free(signal_buffer_list *list);

/**
 * Allocate a new int list
 *
 * @return pointer to the allocated buffer, or 0 on failure
 */
signal_int_list *signal_int_list_alloc(void);

/**
 * Push a new value onto the end of the list
 *
 * @param list the list
 * @param value the value to push
 * @return 0 on success, or negative on failure
 */
int signal_int_list_push_back(signal_int_list *list, int value);

/**
 * Gets the size of the list.
 *
 * @param list the list
 * @return the size of the list
 */
unsigned int signal_int_list_size(signal_int_list *list);

/**
 * Gets the value of the element at a particular index in the list
 *
 * @param list the list
 * @param index the index within the list
 * @return the value
 */
int signal_int_list_at(signal_int_list *list, unsigned int index);

/**
 * Free the int list
 * @param list the list to free
 */
void signal_int_list_free(signal_int_list *list);
""")
