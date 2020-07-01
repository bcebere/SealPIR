#include "benchmark/benchmark.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <random>

#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"
#include "seal/seal.h"

using namespace std::chrono;
using namespace std;
using namespace seal;

uint32_t logt = 12;
uint32_t d = 2;
uint64_t size_per_item = 8;  // in bytes
uint32_t N = 2048;

std::unique_ptr<uint8_t[]> generateDB(std::size_t number_of_items) {
  auto db(make_unique<uint8_t[]>(number_of_items * size_per_item));

  // Copy of the database. We use this at the end to make sure we retrieved
  // the correct element.

  random_device rd;
  for (uint64_t i = 0; i < number_of_items; i++) {
    for (uint64_t j = 0; j < size_per_item; j++) {
      auto val = rd() % 256;
      db.get()[(i * size_per_item) + j] = val;
    }
  }

  return db;
}

void BM_DatabaseLoad(benchmark::State& state) {
  std::size_t dbsize = state.range(0);

  EncryptionParameters params(scheme_type::BFV);
  PirParams pir_params;
  gen_params(dbsize, size_per_item, N, logt, d, params, pir_params);

  PIRServer server(params, pir_params);
  PIRClient client(params, pir_params);
  GaloisKeys galois_keys = client.generate_galois_keys();
  server.set_galois_key(0, galois_keys);

  int64_t elements_processed = 0;
  for (auto _ : state) {
    auto db = move(generateDB(dbsize));
    server.set_database(move(db), dbsize, size_per_item);
    server.preprocess_database();

    ::benchmark::DoNotOptimize(server);
    elements_processed += dbsize;
  }
  state.counters["ElementsProcessed"] = benchmark::Counter(
      static_cast<double>(elements_processed), benchmark::Counter::kIsRate);
}
BENCHMARK(BM_DatabaseLoad)->RangeMultiplier(2)->Range(1 << 12, 1 << 16);

void BM_ClientCreateRequest(benchmark::State& state) {
  std::size_t dbsize = state.range(0);

  EncryptionParameters params(scheme_type::BFV);
  PirParams pir_params;

  gen_params(dbsize, size_per_item, N, logt, d, params, pir_params);

  PIRClient client(params, pir_params);

  uint64_t desiredIndex = 1;  // element in DB at random position
  uint64_t index = client.get_fv_index(desiredIndex,
                                       size_per_item);  // index of FV plaintext
  uint64_t offset = client.get_fv_offset(
      desiredIndex, size_per_item);  // offset in FV plaintext

  int64_t elements_processed = 0;
  for (auto _ : state) {
    PirQuery request = client.generate_query(index);
    ::benchmark::DoNotOptimize(request);
    elements_processed += dbsize;
  }

  state.counters["ElementsProcessed"] = benchmark::Counter(
      static_cast<double>(elements_processed), benchmark::Counter::kIsRate);
}
// Range is for the dbsize.
BENCHMARK(BM_ClientCreateRequest)->RangeMultiplier(2)->Range(1 << 12, 1 << 16);

void BM_ServerProcessRequest(benchmark::State& state) {
  std::size_t dbsize = state.range(0);

  EncryptionParameters params(scheme_type::BFV);
  PirParams pir_params;
  gen_params(dbsize, size_per_item, N, logt, d, params, pir_params);

  auto db = move(generateDB(dbsize));

  PIRServer server(params, pir_params);
  PIRClient client(params, pir_params);

  GaloisKeys galois_keys = client.generate_galois_keys();
  server.set_galois_key(0, galois_keys);

  server.set_database(move(db), dbsize, size_per_item);
  server.preprocess_database();

  uint64_t desired_index = 1;  // element in DB
  uint64_t index = client.get_fv_index(desired_index,
                                       size_per_item);  // index of FV plaintext
  uint64_t offset = client.get_fv_offset(
      desired_index, size_per_item);  // offset in FV plaintext

  PirQuery query = client.generate_query(index);

  int64_t elements_processed = 0;
  for (auto _ : state) {
    PirReply response = server.generate_reply(query, 0);
    ::benchmark::DoNotOptimize(response);
    elements_processed += dbsize;
  }
  state.counters["ElementsProcessed"] = benchmark::Counter(
      static_cast<double>(elements_processed), benchmark::Counter::kIsRate);
}
// Range is for the dbsize.
BENCHMARK(BM_ServerProcessRequest)->RangeMultiplier(2)->Range(1 << 12, 1 << 16);

void BM_ClientProcessResponse(benchmark::State& state) {
  std::size_t dbsize = state.range(0);

  EncryptionParameters params(scheme_type::BFV);
  PirParams pir_params;
  gen_params(dbsize, size_per_item, N, logt, d, params, pir_params);

  auto db = move(generateDB(dbsize));

  PIRServer server(params, pir_params);
  PIRClient client(params, pir_params);

  GaloisKeys galois_keys = client.generate_galois_keys();
  server.set_galois_key(0, galois_keys);

  server.set_database(move(db), dbsize, size_per_item);
  server.preprocess_database();

  uint64_t desired_index = 1;  // element in DB
  uint64_t index = client.get_fv_index(desired_index,
                                       size_per_item);  // index of FV plaintext
  uint64_t offset = client.get_fv_offset(
      desired_index, size_per_item);  // offset in FV plaintext

  PirQuery query = client.generate_query(index);
  PirReply response = server.generate_reply(query, 0);

  int64_t elements_processed = 0;
  for (auto _ : state) {
    Plaintext result = client.decode_reply(response);
    ::benchmark::DoNotOptimize(result);
    elements_processed += dbsize;
  }
  state.counters["ElementsProcessed"] = benchmark::Counter(
      static_cast<double>(elements_processed), benchmark::Counter::kIsRate);
}
// Range is for the dbsize.
BENCHMARK(BM_ClientProcessResponse)
    ->RangeMultiplier(2)
    ->Range(1 << 12, 1 << 16);
