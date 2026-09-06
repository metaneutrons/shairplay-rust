/* SPDX-License-Identifier: MIT */
/* Compile the actual pinned sender callback, not a copy of its encoder. */
#include "module-raop-sink.c"
#include <assert.h>

#define TEST_FRAMES 352u
#define TEST_BYTES (TEST_FRAMES * 4)

static ssize_t packet(struct impl *sender, int receiver, const struct iovec *audio,
		size_t count, uint8_t *output, size_t capacity)
{
	struct rtp_header header = { .v = 2, .pt = 96,
		.sequence_number = htons(23), .timestamp = htonl(44100) };
	struct iovec input[3] = {{ &header, sizeof(header) }};

	assert(count <= 2);
	for (size_t i = 0; i < count; i++)
		input[i + 1] = audio[i];
	stream_send_packet(sender, input, count + 1);
	ssize_t size = recv(receiver, output, capacity, MSG_DONTWAIT);
	assert(size > 0);
	return size;
}

static unsigned int check_splits(struct impl *sender, int receiver)
{
	uint8_t samples[2][TEST_BYTES];
	uint8_t reference[TEST_BYTES + 64], actual[sizeof(reference)];
	const struct iovec contiguous = { samples[0], TEST_BYTES };
	unsigned int failures = 0;

	for (size_t i = 0; i < TEST_BYTES; i++)
		samples[0][i] = samples[1][i] = (uint8_t)(i * 73 + i / 256);
	ssize_t expected = packet(sender, receiver, &contiguous, 1,
			reference, sizeof(reference));
	assert(expected == 12 + TEST_BYTES + 8);
	for (size_t split = 0; split <= TEST_FRAMES; split++) {
		size_t first = split * 4;
		const struct iovec audio[2] = {
			{ samples[0], first }, { samples[1] + first, TEST_BYTES - first }
		};
		ssize_t size = packet(sender, receiver, audio, 2, actual, sizeof(actual));
		if (size != expected || memcmp(actual, reference, (size_t)expected) != 0)
			failures++;
	}
	return failures;
}

int main(int argc, char **argv)
{
	int sockets[2];
	struct impl sender = { .recording = true, .protocol = PROTO_UDP,
		.codec = CODEC_PCM, .stride = 4, .mtu = 1448, .sync_period = UINT32_MAX };

	pw_init(&argc, &argv);
	int result = socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sockets);
	assert(result == 0);
	sender.server_fd = sockets[0];
	unsigned int failures = check_splits(&sender, sockets[1]);
	result = close(sockets[0]);
	assert(result == 0);
	result = close(sockets[1]);
	assert(result == 0);
	pw_deinit();
	printf("{\"cases\":%u,\"failures\":%u}\n", TEST_FRAMES + 2, failures);
	return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
