/*
 * SimuCore: A Comprehensive Ecosystem Simulation Framework
 *
 * Description:
 * SimuCore is a sophisticated ecosystem simulation framework designed to model interactions
 * between various species, environmental factors, and dynamic events. It incorporates
 * multiple data structures, modular components, and advanced C programming techniques
 * to provide a versatile platform for ecological studies and simulations.
 *
 * Features:
 * - Dynamic species and environment management
 * - Event-driven simulation loop
 * - Genetic algorithms for species evolution
 * - Advanced data structures (linked lists, hash tables, trees)
 * - Multithreading for performance optimization
 * - Comprehensive logging and reporting
 *
 * Author: OpenAI ChatGPT
 * Date: 2024-04-27
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <math.h>
#include <stdarg.h>  // Added to handle va_start and va_end

/* ===================== */
/*       Definitions     */
/* ===================== */

#define MAX_SPECIES 100
#define MAX_EVENTS 50
#define HASH_TABLE_SIZE 101
#define MAX_NAME_LENGTH 50
#define MAX_LOG_LENGTH 256
#define THREAD_COUNT 4

/* ===================== */
/*     Data Structures   */
/* ===================== */

/* Genetic Information Structure */
typedef struct {
    double fitness;
    double genes[10];
} Genetics;

/* Species Structure */
typedef struct Species {
    int id;
    char name[MAX_NAME_LENGTH];
    Genetics genetics;
    int population;
    struct Species *next;
} Species;

/* Environment Factors */
typedef struct {
    double temperature;
    double humidity;
    double precipitation;
} Environment;

/* Event Structure */
typedef struct Event {
    int id;
    char description[MAX_NAME_LENGTH];
    void (*handler)(struct Event *, Environment *, Species **, int *);
} Event;

/* Hash Table Entry for Species */
typedef struct HashEntry {
    int key;
    Species *species;
    struct HashEntry *next;
} HashEntry;

/* Hash Table Structure */
typedef struct {
    HashEntry *buckets[HASH_TABLE_SIZE];
} HashTable;

/* Simulation State */
typedef struct {
    Environment env;
    Species *species_list;
    Event *events[MAX_EVENTS];
    int event_count;
    HashTable species_table;
    pthread_mutex_t lock;
    FILE *log_file;
} SimulationState;

/* ===================== */
/*    Utility Functions  */
/* ===================== */

/* Logging Function */
void log_message(SimulationState *state, const char *format, ...) {
    va_list args;
    va_start(args, format);
    char buffer[MAX_LOG_LENGTH];
    vsnprintf(buffer, MAX_LOG_LENGTH, format, args);
    va_end(args);
    pthread_mutex_lock(&state->lock);
    fprintf(state->log_file, "%s\n", buffer);
    pthread_mutex_unlock(&state->lock);
}

/* Hash Function for Species */
unsigned int hash_function(int key) {
    return key % HASH_TABLE_SIZE;
}

/* Initialize Hash Table */
void init_hash_table(HashTable *table) {
    for(int i = 0; i < HASH_TABLE_SIZE; i++) {
        table->buckets[i] = NULL;
    }
}

/* Insert Species into Hash Table */
void hash_table_insert(HashTable *table, Species *species) {
    unsigned int index = hash_function(species->id);
    HashEntry *entry = malloc(sizeof(HashEntry));
    if(entry == NULL){
        perror("Failed to allocate memory for HashEntry");
        exit(EXIT_FAILURE);
    }
    entry->key = species->id;
    entry->species = species;
    entry->next = table->buckets[index];
    table->buckets[index] = entry;
}

/* Search Species in Hash Table */
Species* hash_table_search(HashTable *table, int key) {
    unsigned int index = hash_function(key);
    HashEntry *entry = table->buckets[index];
    while(entry != NULL) {
        if(entry->key == key)
            return entry->species;
        entry = entry->next;
    }
    return NULL;
}

/* Remove Species from Hash Table */
int hash_table_remove(HashTable *table, int key) {
    unsigned int index = hash_function(key);
    HashEntry *entry = table->buckets[index];
    HashEntry *prev = NULL;
    while(entry != NULL) {
        if(entry->key == key) {
            if(prev == NULL)
                table->buckets[index] = entry->next;
            else
                prev->next = entry->next;
            free(entry);
            return 1; // Success
        }
        prev = entry;
        entry = entry->next;
    }
    return 0; // Not found
}

/* ===================== */
/*   Species Management  */
/* ===================== */

/* Create a New Species */
Species* create_species(int id, const char *name, int population) {
    Species *sp = malloc(sizeof(Species));
    if(sp == NULL){
        perror("Failed to allocate memory for Species");
        exit(EXIT_FAILURE);
    }
    sp->id = id;
    strncpy(sp->name, name, MAX_NAME_LENGTH - 1);
    sp->name[MAX_NAME_LENGTH - 1] = '\0'; // Ensure null-termination
    for(int i = 0; i < 10; i++) {
        sp->genetics.genes[i] = ((double)rand()) / RAND_MAX;
    }
    sp->genetics.fitness = 0.0;
    sp->population = population;
    sp->next = NULL;
    return sp;
}

/* Add Species to Simulation */
void add_species(SimulationState *state, Species *species) {
    pthread_mutex_lock(&state->lock);
    species->next = state->species_list;
    state->species_list = species;
    hash_table_insert(&state->species_table, species);
    log_message(state, "Added species: %s (ID: %d, Population: %d)", species->name, species->id, species->population);
    pthread_mutex_unlock(&state->lock);
}

/* Remove Species from Simulation */
void remove_species(SimulationState *state, int species_id) {
    pthread_mutex_lock(&state->lock);
    Species *current = state->species_list;
    Species *prev = NULL;
    while(current != NULL) {
        if(current->id == species_id) {
            if(prev == NULL)
                state->species_list = current->next;
            else
                prev->next = current->next;
            hash_table_remove(&state->species_table, species_id);
            log_message(state, "Removed species: %s (ID: %d)", current->name, current->id);
            free(current);
            pthread_mutex_unlock(&state->lock);
            return;
        }
        prev = current;
        current = current->next;
    }
    log_message(state, "Species ID %d not found for removal.", species_id);
    pthread_mutex_unlock(&state->lock);
}

/* Update Species Fitness */
void update_fitness(SimulationState *state, int species_id, double fitness) {
    pthread_mutex_lock(&state->lock);
    Species *sp = hash_table_search(&state->species_table, species_id);
    if(sp != NULL) {
        sp->genetics.fitness = fitness;
        log_message(state, "Updated fitness for species %s (ID: %d) to %.2f", sp->name, sp->id, fitness);
    } else {
        log_message(state, "Species ID %d not found for fitness update.", species_id);
    }
    pthread_mutex_unlock(&state->lock);
}

/* ===================== */
/*      Events Handling  */
/* ===================== */

/* Example Event Handlers */
void drought_event_handler(Event *event, Environment *env, Species **species_list, int *species_count) {
    env->temperature += 5.0;
    env->precipitation -= 10.0;
    printf("Event: %s occurred. Temperature increased and precipitation decreased.\n", event->description);
}

void flood_event_handler(Event *event, Environment *env, Species **species_list, int *species_count) {
    env->humidity += 20.0;
    env->precipitation += 30.0;
    printf("Event: %s occurred. Humidity and precipitation increased.\n", event->description);
}

void fire_event_handler(Event *event, Environment *env, Species **species_list, int *species_count) {
    // Reduce population of all species by 10%
    Species *current = *species_list;
    while(current != NULL) {
        current->population = (int)(current->population * 0.9);
        current = current->next;
    }
    printf("Event: %s occurred. Population of all species reduced by 10%%.\n", event->description);
}

/* Register Events */
void register_events(SimulationState *state) {
    for(int i = 0; i < 3; i++) {
        Event *evt = malloc(sizeof(Event));
        if(evt == NULL){
            perror("Failed to allocate memory for Event");
            exit(EXIT_FAILURE);
        }
        evt->id = i;
        switch(i) {
            case 0:
                strcpy(evt->description, "Drought");
                evt->handler = drought_event_handler;
                break;
            case 1:
                strcpy(evt->description, "Flood");
                evt->handler = flood_event_handler;
                break;
            case 2:
                strcpy(evt->description, "Wildfire");
                evt->handler = fire_event_handler;
                break;
            default:
                strcpy(evt->description, "Unknown");
                evt->handler = NULL;
        }
        state->events[state->event_count++] = evt;
    }
}

/* Trigger Random Event */
void trigger_random_event(SimulationState *state) {
    if(state->event_count == 0) return;
    int idx = rand() % state->event_count;
    Event *evt = state->events[idx];
    evt->handler(evt, &state->env, &state->species_list, NULL);
    log_message(state, "Event triggered: %s", evt->description);
}

/* ===================== */
/*  Genetic Algorithm    */
/* ===================== */

/* Evolve Species Genetics */
void evolve_genetics(SimulationState *state) {
    pthread_mutex_lock(&state->lock);
    Species *current = state->species_list;
    while(current != NULL) {
        for(int i = 0; i < 10; i++) {
            current->genetics.genes[i] += (((double)rand()) / RAND_MAX - 0.5) * 0.1;
            // Ensure genes stay within [0,1] range
            if(current->genetics.genes[i] < 0.0) current->genetics.genes[i] = 0.0;
            if(current->genetics.genes[i] > 1.0) current->genetics.genes[i] = 1.0;
        }
        // Recalculate fitness based on some criteria
        current->genetics.fitness = 0.0;
        for(int i = 0; i < 10; i++) {
            current->genetics.fitness += current->genetics.genes[i] * current->genetics.genes[i];
        }
        current = current->next;
    }
    pthread_mutex_unlock(&state->lock);
    log_message(state, "Genetics evolved for all species.");
}

/* ===================== */
/*     Simulation Loop   */
/* ===================== */

/* Simulation Step */
void simulation_step(SimulationState *state, int step_number) {
    log_message(state, "Simulation Step %d started.", step_number);
    // Update environment factors
    state->env.temperature += ((double)rand() / RAND_MAX - 0.5);
    state->env.humidity += ((double)rand() / RAND_MAX - 0.5);
    state->env.precipitation += ((double)rand() / RAND_MAX - 0.5);
    log_message(state, "Environment updated: Temp=%.2f, Humidity=%.2f, Precipitation=%.2f",
                state->env.temperature, state->env.humidity, state->env.precipitation);
    // Trigger random events
    if(rand() % 10 < 2) { // 20% chance
        trigger_random_event(state);
    }
    // Evolve genetics
    evolve_genetics(state);
    // Population dynamics
    pthread_mutex_lock(&state->lock);
    Species *current = state->species_list;
    while(current != NULL) {
        // Simple population growth model
        current->population += (int)(current->population * (current->genetics.fitness / 100.0));
        if(current->population < 0) current->population = 0;
        log_message(state, "Species %s (ID: %d) population: %d", current->name, current->id, current->population);
        current = current->next;
    }
    pthread_mutex_unlock(&state->lock);
    log_message(state, "Simulation Step %d completed.", step_number);
}

/* ===================== */
/*    Multithreading     */
/* ===================== */

/* Thread Function */
typedef struct {
    SimulationState *state;
    int start_step;
    int end_step;
} ThreadData;

void* thread_simulation(void *arg) {
    ThreadData *data = (ThreadData*)arg;
    for(int i = data->start_step; i <= data->end_step; i++) {
        simulation_step(data->state, i);
    }
    return NULL;
}

/* ===================== */
/*      Initialization   */
/* ===================== */

/* Initialize Simulation State */
SimulationState* initialize_simulation(const char *log_filename) {
    SimulationState *state = malloc(sizeof(SimulationState));
    if(state == NULL){
        perror("Failed to allocate memory for SimulationState");
        exit(EXIT_FAILURE);
    }
    state->env.temperature = 20.0;
    state->env.humidity = 50.0;
    state->env.precipitation = 30.0;
    state->species_list = NULL;
    state->event_count = 0;
    init_hash_table(&state->species_table);
    if(pthread_mutex_init(&state->lock, NULL) != 0){
        perror("Mutex initialization failed");
        free(state);
        exit(EXIT_FAILURE);
    }
    state->log_file = fopen(log_filename, "w");
    if(state->log_file == NULL) {
        perror("Failed to open log file");
        free(state);
        exit(EXIT_FAILURE);
    }
    register_events(state);
    log_message(state, "Simulation initialized.");
    return state;
}

/* ===================== */
/*      Cleanup          */
/* ===================== */

/* Cleanup Simulation State */
void cleanup_simulation(SimulationState *state) {
    // Free species
    Species *current = state->species_list;
    while(current != NULL) {
        Species *tmp = current;
        current = current->next;
        free(tmp);
    }
    // Free events
    for(int i = 0; i < state->event_count; i++) {
        free(state->events[i]);
    }
    // Free hash table
    for(int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashEntry *entry = state->species_table.buckets[i];
        while(entry != NULL) {
            HashEntry *tmp = entry;
            entry = entry->next;
            free(tmp);
        }
    }
    fclose(state->log_file);
    pthread_mutex_destroy(&state->lock);
    free(state);
    printf("Simulation cleaned up.\n");
}

/* ===================== */
/*        Main           */
/* ===================== */

int main() {
    srand(time(NULL));
    SimulationState *state = initialize_simulation("simulation.log");

    // Add initial species
    add_species(state, create_species(1, "Lions", 50));
    add_species(state, create_species(2, "Elephants", 30));
    add_species(state, create_species(3, "Grass", 1000));
    add_species(state, create_species(4, "Rabbits", 200));

    // Define simulation steps
    int total_steps = 100;
    int steps_per_thread = total_steps / THREAD_COUNT;
    pthread_t threads[THREAD_COUNT];
    ThreadData thread_data[THREAD_COUNT];

    // Create threads
    for(int i = 0; i < THREAD_COUNT; i++) {
        thread_data[i].state = state;
        thread_data[i].start_step = i * steps_per_thread + 1;
        thread_data[i].end_step = (i == THREAD_COUNT - 1) ? total_steps : (i + 1) * steps_per_thread;
        if(pthread_create(&threads[i], NULL, thread_simulation, &thread_data[i]) != 0){
            perror("Failed to create thread");
            cleanup_simulation(state);
            exit(EXIT_FAILURE);
        }
    }

    // Join threads
    for(int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
    }

    // Final report
    log_message(state, "Simulation completed after %d steps.", total_steps);
    printf("Simulation completed. Check 'simulation.log' for details.\n");

    // Cleanup
    cleanup_simulation(state);
    return 0;
}