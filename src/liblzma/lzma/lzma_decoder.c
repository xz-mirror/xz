///////////////////////////////////////////////////////////////////////////////
//
/// \file       lzma_decoder.c
/// \brief      LZMA decoder
///
//  Authors:    Igor Pavlov
//              Lasse Collin
//
//  This file has been put into the public domain.
//  You can do whatever you want with this file.
//
///////////////////////////////////////////////////////////////////////////////

#include "lz_decoder.h"
#include "lzma_common.h"
#include "lzma_decoder.h"
#include "range_decoder.h"

// The macros unroll loops with switch statements.
// Silence warnings about missing fall-through comments.
#if TUKLIB_GNUC_REQ(7, 0)
#	pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#endif

// Minimum number of input bytes to safely decode one LZMA symbol.
// The worst case is that we decode 22 bits using probabilities and 26
// direct bits. This may decode at maximum 20 bytes of input.
#define LZMA_IN_REQUIRED 20

//////////////////////////////
// Probability Model macros //
//////////////////////////////
//
// The Probability Models are combined into one contiguous array.
// The macros are used to calculate the start offset for the separate
// models contained in the array. Each sub-model consists of 2-3 macros:
//
// - The offset macro. This macro represents the number of probabilities
//   between the base pointer to the beginning of the specific model. It
//   is calculated using:
//   previous offset macro + previous prob count macro.
//
// - The prob count macro. This represents the total number of
//   probabilities needed by the sub-model. Some sub-models do not
//   have this explicitly defined if the size is defined somewhere else.
//
// - The model macro. The arguments always include the base model pointer
//   as the first argument. Optionally, the state or the position state are
//   needed to find the correct sub-model.
//
// The macros that begin with "is_" are used to decode a single bit.
// The other macros will decode multiple bits contiguously.
//
// These macros can be reused in an assembly version of the decoder
// to simplify the implementation.

// The start offset alters the pointer that is used for the base of the
// model to optimize the most used probabilities to be closest to the
// pointer. Currently the offset to is_rep_model() is the new offset 0.
#define MODEL_START_OFFSET (POS_SPECIAL_PROB_COUNT \
		+ IS_REP0_PROB_COUNT \
		+ LEN_MODEL_PROB_COUNT * 2 \
		+ IS_MATCH_MODEL_PROB_COUNT + ALIGN_SIZE)

// The position special probability tree is used to decode the low bits
// of the simple match distance when the match distance is in the range
// [4, 127].
#define POS_SPECIAL_OFFSET (-MODEL_START_OFFSET)
#define POS_SPECIAL_PROB_COUNT (FULL_DISTANCES - DIST_MODEL_END)
#define pos_special_model(model) (model + POS_SPECIAL_OFFSET)

// The repeated match 0 long model decodes a single bit to determine if the
// repeated match has a length of only 1 byte. If so, 1 byte is repeated
// from the last distance used by a simple or repeated match. This does not
// update the distance history cache.
#define IS_REP0_LONG_OFFSET (POS_SPECIAL_OFFSET + POS_SPECIAL_PROB_COUNT)
#define IS_REP0_PROB_COUNT (STATES << LZMA_PB_MAX)
#define is_rep0_long_model(model, state, pos_state) (model \
		+ IS_REP0_LONG_OFFSET + state + pos_state)

// The repeated length model is used to decode the length (number
// of bytes to repeat from the dictionary) of the repeated match.
// The distance (how far back in the dictionary to start copying)
// is determined through the is_repX models that are defined later
// This size of this sub-model is defined later as LEN_MODEL_PROB_COUNT.
#define REP_LENGTH_MODEL_OFFSET (IS_REP0_LONG_OFFSET + IS_REP0_PROB_COUNT)
#define rep_length_model(model) (model + REP_LENGTH_MODEL_OFFSET)

// The match length model is used to decode the length of a simple
// match. Simple matches must also decode the distance. This size of
// this sub-model is defined later as LEN_MODEL_PROB_COUNT.
#define MATCH_LENGTH_OFFSET (REP_LENGTH_MODEL_OFFSET \
		+ LEN_MODEL_PROB_COUNT)
#define match_length_model(model) (model + MATCH_LENGTH_OFFSET)

// The "is match" model determines if the next symbol is a literal or a match.
#define IS_MATCH_MODEL_OFFSET (MATCH_LENGTH_OFFSET \
		+ LEN_MODEL_PROB_COUNT)
#define IS_MATCH_MODEL_PROB_COUNT (STATES << LZMA_PB_MAX)
#define is_match_model(model, pos_state, state) (model \
		+ IS_MATCH_MODEL_OFFSET + pos_state + state)

// The position align probability tree is used to decode the lowest
// four bits of the match distance when the distance is greater than 127.
#define POS_ALIGN_OFFSET (IS_MATCH_MODEL_OFFSET + IS_MATCH_MODEL_PROB_COUNT)
#define pos_align_model(model) ((model) + POS_ALIGN_OFFSET)

// The "is rep" model decodes a single bit to determine if the match is a
// simple match (0) or a repeated match (1).
#define IS_REP_OFFSET (POS_ALIGN_OFFSET + ALIGN_SIZE)
#define is_rep_model(model, state) (model + (IS_REP_OFFSET + state))

// The "is rep 0" model decodes a single bit to determine if the repeated
// match should use rep0 as the distance (0) or check the rep 1 model.
#define IS_REP0_OFFSET (IS_REP_OFFSET + STATES)
#define is_rep0_model(model, state) (model + (IS_REP0_OFFSET + state))

// The "is rep 1" model decodes a single bit to determine if the repeated
// match should use rep1 as the distance (0) or check the rep 2 model.
#define IS_REP1_OFFSET (IS_REP0_OFFSET + STATES)
#define is_rep1_model(model, state) (model + (IS_REP1_OFFSET + state))

// The "is rep 2" model decodes a single bit to determine if the repeated
// match should use rep2 as the distance (0) or rep3 (1).
#define IS_REP2_OFFSET (IS_REP1_OFFSET + STATES)
#define is_rep2_model(model, state) (model + (IS_REP2_OFFSET + state))

// The distance slot probability tree is used to decode six bits, which
// determine the highest two bits of the match distance and how to decode
// the rest of the match distance.
#define DIST_SLOT_OFFSET (IS_REP2_OFFSET + STATES)
#define DIST_SLOT_PROB_COUNT (DIST_STATES << DIST_SLOT_BITS)
#define dist_slot_model(model) (model + DIST_SLOT_OFFSET)

// The literal model is used to decode 1 byte.
#define LITERAL_OFFSET (DIST_SLOT_OFFSET + DIST_SLOT_PROB_COUNT)
#define LITERAL_PROB_COUNT ((uint32_t) LITERAL_CODER_SIZE << LZMA_LCLP_MAX)
#define literal_model(model) (model + LITERAL_OFFSET)

// Select the literal sub-model from the base of the literal probability
// tables. The table is selected by a context from lc number of high bits
// from the previous literal combined with lp number of low bits from the
// current location in the output stream. The context must be multiplied
// by 0x300 to select the correct sub-table. The formula below is optimized
// to only need to multiply by 3 because of the way the literal position
// mask was created in lzma_decoder_reset().
#define literal_subdecoder(model, dict, lp_mask, lc) model \
		+ (uint32_t) 3 * ((((dict.pos << 8) + dict_get(&dict, 0)) \
		& lp_mask) << lc);

// The total number of probability values needed for the entire model.
#define PROBABILITY_COUNT (LITERAL_OFFSET \
		+ LITERAL_PROB_COUNT \
		+ MODEL_START_OFFSET)

// The match length macros are relative to the beginning of the models.
// LZMA uses two different match length models:
// - Simple match length
// - Repeated match length
#define LEN_MODEL_CHOICE_OFFSET 0
#define LEN_MODEL_CHOICE_2_OFFSET (LEN_MODEL_CHOICE_OFFSET + LEN_LOW_SYMBOLS)

#define LEN_MODEL_HIGH_OFFSET (LEN_MODEL_CHOICE_OFFSET \
		+ ((1 << LZMA_PB_MAX) << LEN_LOW_BITS) \
		+ ((1 << LZMA_PB_MAX) << LEN_MID_BITS))

#define LEN_MODEL_PROB_COUNT (LEN_MODEL_HIGH_OFFSET + LEN_HIGH_SYMBOLS)

// Macros for (somewhat) size-optimized code.
// This is used to decode the match length (how many bytes must be repeated
// from the dictionary). This version is used in the Resumable mode and
// does not unroll any loops.
#define len_decode(target, sub_tree, prob_tree, pos_state, seq) \
do { \
case seq ## _CHOICE: \
	rc_if_0_safe(sub_tree, seq ## _CHOICE) { \
		rc_update_0(sub_tree); \
		sub_tree += pos_state; \
		limit = LEN_LOW_SYMBOLS; \
		target = MATCH_LEN_MIN; \
	} else { \
		rc_update_1(sub_tree); \
		sub_tree += LEN_MODEL_CHOICE_2_OFFSET; \
case seq ## _CHOICE2: \
		rc_if_0_safe(sub_tree, seq ## _CHOICE2) { \
			rc_update_0(sub_tree); \
			sub_tree += pos_state; \
			limit = LEN_MID_SYMBOLS; \
			target = MATCH_LEN_MIN + LEN_LOW_SYMBOLS; \
		} else { \
			rc_update_1(sub_tree); \
			sub_tree = prob_tree + LEN_MODEL_HIGH_OFFSET; \
			limit = LEN_HIGH_SYMBOLS; \
			target = MATCH_LEN_MIN + LEN_LOW_SYMBOLS \
					+ LEN_MID_SYMBOLS; \
		} \
	} \
	symbol = 1; \
case seq ## _BITTREE: \
	do { \
		rc_bit_safe(sub_tree + symbol, , , seq ## _BITTREE); \
	} while (symbol < limit); \
	target += symbol - limit; \
} while (0)


// This is the faster version of the match length decoder that does not
// worry about being resumable. It unrolls the bittree decoding loop.
#define len_decode_fast(target, prob_tree, pos_state) \
do { \
	symbol = 1; \
	probability *sub_tree = prob_tree; \
	rc_if_0(sub_tree) { \
		rc_update_0(sub_tree); \
		sub_tree += pos_state; \
		rc_bit(sub_tree + symbol, , ); \
		rc_bit(sub_tree + symbol, , ); \
		rc_bit(sub_tree + symbol, , ); \
		target = symbol - LEN_LOW_SYMBOLS + MATCH_LEN_MIN; \
	} else { \
		rc_update_1(sub_tree); \
		sub_tree += LEN_MODEL_CHOICE_2_OFFSET; \
		rc_if_0(sub_tree) { \
			rc_update_0(sub_tree); \
			sub_tree += pos_state; \
			rc_bit(sub_tree + symbol, , ); \
			rc_bit(sub_tree + symbol, , ); \
			rc_bit(sub_tree + symbol, , ); \
			target = symbol - LEN_MID_SYMBOLS \
					+ MATCH_LEN_MIN + LEN_LOW_SYMBOLS; \
		} else { \
			rc_update_1(sub_tree); \
			sub_tree = prob_tree + LEN_MODEL_HIGH_OFFSET; \
			rc_bit(sub_tree + symbol, , ); \
			rc_bit(sub_tree + symbol, , ); \
			rc_bit(sub_tree + symbol, , ); \
			rc_bit(sub_tree + symbol, , ); \
			rc_bit(sub_tree + symbol, , ); \
			rc_bit(sub_tree + symbol, , ); \
			rc_bit(sub_tree + symbol, , ); \
			rc_bit(sub_tree + symbol, , ); \
			target = symbol - LEN_HIGH_SYMBOLS \
					+ MATCH_LEN_MIN \
					+ LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS; \
		} \
	} \
} while (0)


typedef struct {
	///////////////////
	// Probabilities //
	///////////////////

	probability model[PROBABILITY_COUNT];

	///////////////////
	// Decoder state //
	///////////////////

	// Range coder
	lzma_range_decoder rc;

	// Types of the most recently seen LZMA symbols
	lzma_lzma_state state;

	uint32_t rep0;      ///< Distance of the latest match
	uint32_t rep1;      ///< Distance of second latest match
	uint32_t rep2;      ///< Distance of third latest match
	uint32_t rep3;      ///< Distance of fourth latest match

	uint32_t pos_mask; // (1U << pb) - 1
	uint32_t literal_context_bits;
	uint32_t literal_pos_mask;

	/// Uncompressed size as bytes, or LZMA_VLI_UNKNOWN if end of
	/// payload marker is expected.
	lzma_vli uncompressed_size;

	/// True if end of payload marker (EOPM) is allowed even when
	/// uncompressed_size is known; false if EOPM must not be present.
	/// This is ignored if uncompressed_size == LZMA_VLI_UNKNOWN.
	bool allow_eopm;

	////////////////////////////////
	// State of incomplete symbol //
	////////////////////////////////

	/// Position where to continue the decoder loop
	enum {
		SEQ_NORMALIZE,
		SEQ_IS_MATCH,
		SEQ_LITERAL,
		SEQ_LITERAL_MATCHED,
		SEQ_LITERAL_WRITE,
		SEQ_IS_REP,
		SEQ_MATCH_LEN_CHOICE,
		SEQ_MATCH_LEN_CHOICE2,
		SEQ_MATCH_LEN_BITTREE,
		SEQ_DIST_SLOT,
		SEQ_DIST_MODEL,
		SEQ_DIRECT,
		SEQ_ALIGN,
		SEQ_EOPM,
		SEQ_IS_REP0,
		SEQ_SHORTREP,
		SEQ_IS_REP0_LONG,
		SEQ_IS_REP1,
		SEQ_IS_REP2,
		SEQ_REP_LEN_CHOICE,
		SEQ_REP_LEN_CHOICE2,
		SEQ_REP_LEN_BITTREE,
		SEQ_COPY,
	} sequence;

	/// Base of the current probability tree
	probability *probs;

	/// Symbol being decoded. This is also used as an index variable in
	/// bittree decoders: probs[symbol]
	uint32_t symbol;

	/// Used as a loop termination condition on bittree decoders and
	/// direct bits decoder.
	uint32_t limit;

	/// Matched literal decoder: 0x100 or 0 to help avoiding branches.
	/// Bittree reverse decoders: Offset of the next bit: 1 << offset
	uint32_t offset;

	/// If decoding a literal: match byte.
	/// If decoding a match: length of the match.
	uint32_t len;
} lzma_lzma1_decoder;


static lzma_ret
lzma_decode(void *coder_ptr, lzma_dict *restrict dictptr,
		const uint8_t *restrict in,
		size_t *restrict in_pos, size_t in_size)
{
	lzma_lzma1_decoder *restrict coder = coder_ptr;

	////////////////////
	// Initialization //
	////////////////////

	{
		const lzma_ret ret = rc_read_init(
				&coder->rc, in, in_pos, in_size);
		if (ret != LZMA_STREAM_END)
			return ret;
	}

	///////////////
	// Variables //
	///////////////

	// Making local copies of often-used variables improves both
	// speed and readability.

	lzma_dict dict = *dictptr;

	const size_t dict_start = dict.pos;

	// Range decoder
	rc_to_local(coder->rc, *in_pos);

	// State
	uint32_t state = coder->state;
	uint32_t rep0 = coder->rep0;
	uint32_t rep1 = coder->rep1;
	uint32_t rep2 = coder->rep2;
	uint32_t rep3 = coder->rep3;

	const uint32_t pos_mask = coder->pos_mask;

	// These variables are actually needed only if we last time ran
	// out of input in the middle of the decoder loop.
	probability *probs = coder->probs;
	uint32_t symbol = coder->symbol;
	uint32_t limit = coder->limit;
	uint32_t offset = coder->offset;
	uint32_t len = coder->len;

	const uint32_t literal_pos_mask = coder->literal_pos_mask;
	const uint32_t literal_context_bits = coder->literal_context_bits;

	// Temporary variables
	uint32_t pos_state = (dict.pos & pos_mask) << LZMA_PB_MAX;

	lzma_ret ret = LZMA_OK;

	// This is true when the next LZMA symbol is allowed to be EOPM.
	// That is, if this is false, then EOPM is considered
	// an invalid symbol and we will return LZMA_DATA_ERROR.
	//
	// EOPM is always required (not just allowed) when
	// the uncompressed size isn't known. When uncompressed size
	// is known, eopm_is_valid may be set to true later.
	bool eopm_is_valid = coder->uncompressed_size == LZMA_VLI_UNKNOWN;

	// If uncompressed size is known and there is enough output space
	// to decode all the data, limit the available buffer space so that
	// the main loop won't try to decode past the end of the stream.
	bool might_finish_without_eopm = false;
	if (coder->uncompressed_size != LZMA_VLI_UNKNOWN
			&& coder->uncompressed_size <= dict.limit - dict.pos) {
		dict.limit = dict.pos + (size_t)(coder->uncompressed_size);
		might_finish_without_eopm = true;
	}

	// Lookup table used to update the literal state.
	// Compared to other state updates, this would need two branches.
	// The lookup table is used by both Resumable and Non-resumable modes.
	static const lzma_lzma_state next_state[] = {
		STATE_LIT_LIT,
		STATE_LIT_LIT,
		STATE_LIT_LIT,
		STATE_LIT_LIT,
		STATE_MATCH_LIT_LIT,
		STATE_REP_LIT_LIT,
		STATE_SHORTREP_LIT_LIT,
		STATE_MATCH_LIT,
		STATE_REP_LIT,
		STATE_SHORTREP_LIT,
		STATE_MATCH_LIT,
		STATE_REP_LIT
	};

	// The main decoder loop. The "switch" is used to resume the decoder at
	// correct location. Once resumed, the "switch" is no longer used.
	// The decoder loops is split into two modes:
	//
	// 1 - Non-resumable mode (fast). This is used when it is guaranteed
	//     there is enough input to decode the next symbol. If the output
	//     limit is reached, then the decoder loop will save the place
	//     for the resumable mode to continue. This mode is not used if
	//     HAVE_SMALL is defined. This is faster than Resumable mode
	//     because it reduces the number of branches needed and allows
	//     for more compiler optimizations.
	//
	// 2 - Resumable mode (slow). This is used when a previous decoder
	//     loop did not have enough space in the input or output buffers
	//     to complete. It uses sequence enum values to set remind
	//     coder->sequence where to resume in the decoder loop. This
	//     is the only mode used when HAVE_SMALL is defined.

	probability *model_base = coder->model + MODEL_START_OFFSET;

	switch (coder->sequence)
	while (true) {
		// Calculate new pos_state. This is skipped on the first loop
		// since we already calculated it when setting up the local
		// variables.
		pos_state = (dict.pos & pos_mask) << LZMA_PB_MAX;

#ifndef HAVE_SMALL

		///////////////////////////////
		// Non-resumable Mode (fast) //
		///////////////////////////////

		// If there is not enough room for another LZMA symbol
		// go to Resumable mode.
		if (rc_in_pos + LZMA_IN_REQUIRED > in_size
			|| dict.pos == dict.limit)
			goto slow;

		// Decode the first bit from the next LZMA symbol.
		// If the bit is a 0, then we handle it as a literal.
		// If the bit is a 1, then it is a match of previously
		// decoded data.
		probability *model = is_match_model(model_base, pos_state,
				state);
		rc_if_0(model) {
			/////////////////////
			// Decode literal. //
			/////////////////////

			// Update the RC that we have decoded a 0.
			rc_update_0(model);

			// Get the correct probability table from
			// lp and lc params.
			model = literal_subdecoder(literal_model(model_base),
					dict, literal_pos_mask,
					literal_context_bits);
			symbol = 1;

			if (is_literal_state(state)) {
				// Decode literal without match byte.
				// We need to decode 8 bits, so instead
				// of looping from 1 - 8, we unroll the
				// loop for a speed optimization.
				rc_bit(model + symbol, , );
				rc_bit(model + symbol, , );
				rc_bit(model + symbol, , );
				rc_bit(model + symbol, , );
				rc_bit(model + symbol, , );
				rc_bit(model + symbol, , );
				rc_bit(model + symbol, , );
				rc_bit(model + symbol, , );
			} else {
				// Decode literal with match byte.
				//
				// We store the byte we compare against
				// ("match byte") to "len" to minimize the
				// number of variables we need to store
				// between decoder calls.

				len = (uint32_t)(dict_get(&dict, rep0)) << 1;

				// The usage of "offset" allows omitting some
				// branches, which should give tiny speed
				// improvement on some CPUs. "offset" gets
				// set to zero if match_bit didn't match.
				offset = 0x100;

				// Unroll the loop.
				uint32_t match_bit;
				uint32_t subcoder_index;

#	define decode_with_match_bit \
			match_bit = len & offset; \
			subcoder_index = offset + match_bit + symbol; \
			rc_bit(model + subcoder_index, \
					offset &= ~match_bit, \
					offset &= match_bit)

				decode_with_match_bit;
				len <<= 1;
				decode_with_match_bit;
				len <<= 1;
				decode_with_match_bit;
				len <<= 1;
				decode_with_match_bit;
				len <<= 1;
				decode_with_match_bit;
				len <<= 1;
				decode_with_match_bit;
				len <<= 1;
				decode_with_match_bit;
				len <<= 1;
				decode_with_match_bit;
#	undef decode_match_bit
			}

			state = next_state[state];

			// Write decoded literal to dictionary
			dict_put(&dict, symbol);

			continue;
		}

		///////////////////
		// Decode match. //
		///////////////////

		// Instead of a new byte we are going to decode a
		// distance-length pair. The distance represents how far
		// back in the dictionary to begin copying. The length
		// represents how many bytes to copy.

		rc_update_1(model);

		model = is_rep_model(model_base, state);
		rc_if_0(model) {
			///////////////////
			// Simple match. //
			///////////////////

			// Not a repeated match. In this case,
			// the length (how many bytes to copy) must be
			// decoded first. Then, the distance (where to
			// start copying) is decoded.
			//
			// This is also how we know when we are done
			// decoding. If the distance decodes to UINT32_MAX,
			// then we know to stop decoding (end of payload
			// marker).

			rc_update_0(model);
			update_match(state);

			// The latest three match distances are kept in
			// memory in case there are repeated matches.
			rep3 = rep2;
			rep2 = rep1;
			rep1 = rep0;

			// Decode the length of the match.
			len_decode_fast(len, match_length_model(model_base),
					pos_state);

			// Next, decode the distance into rep0.

			// The next 6 bits determine how to decode the
			// rest of the distance.
			model = dist_slot_model(model_base)
				+ (get_dist_state(len) << DIST_SLOT_BITS);
			symbol = 1;

			rc_bit(model + symbol, , );
			rc_bit(model + symbol, , );
			rc_bit(model + symbol, , );
			rc_bit(model + symbol, , );
			rc_bit(model + symbol, , );
			rc_bit(model + symbol, , );

			// Get rid of the highest bit that was needed for
			// indexing of the probability array.
			symbol -= DIST_SLOTS;
			assert(symbol <= 63);

			if (symbol < DIST_MODEL_START) {
				// If the decoded symbol is < DIST_MODEL_START
				// then we use its value directly as the
				// match distance. No other bits are needed.
				// The only possible distance values
				// are [0, 3].
				rep0 = symbol;
			} else {
				// Use the first two bits of symbol as the
				// highest bits of the match distance.

				// "limit" represents the number of low bits
				// to decode.
				limit = (symbol >> 1) - 1;
				assert(limit >= 1 && limit <= 30);
				rep0 = 2 + (symbol & 1);

				if (symbol < DIST_MODEL_END) {
					// When symbol is > DIST_MODEL_START,
					// but symbol < DIST_MODEL_END, then
					// it can decode distances between
					// [4, 127].
					assert(limit <= 5);
					rep0 <<= limit;
					assert(rep0 <= 96);
					// -1 is fine, because we start
					// decoding at model[1], not model[0].
					// NOTE: This violates the C standard,
					// since we are doing pointer
					// arithmetic past the beginning of
					// the array.
					assert((int32_t)(rep0 - symbol - 1)
							>= -1);
					assert((int32_t)(rep0 - symbol - 1)
							<= 82);

					model = pos_special_model(model_base)
							+ rep0
							- symbol - 1;
					symbol = 1;
					offset = 0;

					switch (limit) {
					case 5:
						assert(offset == 0);
						rc_bit(model + symbol, ,
							rep0 += 1U);
						++offset;
						--limit;
					case 4:
						rc_bit(model + symbol, ,
							rep0 += 1U << offset);
						++offset;
						--limit;
					case 3:
						rc_bit(model + symbol, ,
							rep0 += 1U << offset);
						++offset;
						--limit;
					case 2:
						rc_bit(model + symbol, ,
							rep0 += 1U << offset);
						++offset;
						--limit;
					case 1:
						// We need "symbol" only for
						// indexing the probability
						// array, thus we can use
						// rc_bit_last() here to
						// omit the unneeded updating
						// of "symbol".
						rc_bit_last(model + symbol, ,
							rep0 += 1U << offset);
					}
				} else {
					// The distance is >= 128. Decode the
					// lower bits without probabilities
					// except the lowest four bits.
					assert(symbol >= 14);
					assert(limit >= 6);
					limit -= ALIGN_BITS;
					assert(limit >= 2);

					// Not worth manual unrolling
					do {
						rc_direct(rep0);
					} while (--limit > 0);

					// Decode the lowest four bits using
					// probabilities.
					rep0 <<= ALIGN_BITS;
					symbol = 1;
					model = pos_align_model(model_base);


					rc_bit(model + symbol, ,
							rep0 += 1);

					rc_bit(model + symbol, ,
							rep0 += 2);

					rc_bit(model + symbol, ,
							rep0 += 4);

					// Like when distance [4, 127], we
					// don't need "symbol" for anything
					// other than indexing the probability
					// array.
					rc_bit_last(
						model + symbol, ,
						rep0 += 8);

					if (rep0 == UINT32_MAX) {
						///////////////////////////
						// End of payload marker //
						///////////////////////////

						// End of payload marker was
						// found. It may only be
						// present if
						//   - uncompressed size is
						//     unknown or
						//   - after known uncompressed
						//     size amount of bytes has
						//     been decompressed and
						//     caller has indicated
						//     that EOPM might be used
						//     (it's not allowed in
						//     LZMA2).
						if (!eopm_is_valid) {
							ret = LZMA_DATA_ERROR;
							goto out;
						}

						// LZMA1 stream with
						// end-of-payload marker.
						rc_normalize();
						ret = rc_is_finished(rc)
							? LZMA_STREAM_END
							: LZMA_DATA_ERROR;
						goto out;
					}
				}
			}

			// Validate the distance we just decoded.
			if (unlikely(!dict_is_distance_valid(&dict, rep0))) {
				ret = LZMA_DATA_ERROR;
				goto out;
			}

		} else {
			rc_update_1(model);
			/////////////////////
			// Repeated match. //
			/////////////////////

			// The match distance is a value that we have decoded
			// recently. The latest four match distances are
			// available as rep0, rep1, rep2 and rep3. We will
			// now decode which of them is the new distance.
			//
			// There cannot be a match if we haven't produced
			// any output, so check that first.
			if (unlikely(!dict_is_distance_valid(&dict, 0))) {
				ret = LZMA_DATA_ERROR;
				goto out;
			}

			model = is_rep0_model(model_base, state);
			rc_if_0(model) {
				rc_update_0(model);
				// The distance is rep0.

				// Decode the next bit to determine if 1 byte
				// should be copied from rep0 distance or
				// if the number of bytes needs to be decoded.

				// If the next bit is 0, then it is a
				// "Short Rep Match" and only 1 bit is copied.
				// Otherwise, the length of the match is
				// decoded after the "else" statement.
				model = is_rep0_long_model(model_base, state,
						pos_state);

				rc_if_0(model) {
					rc_update_0(model);

					update_short_rep(state);
					dict_put(&dict, dict_get(&dict, rep0));
					continue;
				}

				// Repeating more than one byte at
				// distance of rep0.
				rc_update_1(model);

			} else {
				rc_update_1(model);

				// The distance is rep1, rep2 or rep3. Once
				// we find out which one of these three, it
				// is stored to rep0 and rep1, rep2 and rep3
				// are updated accordingly. There is no
				// "Short Rep Match" option, so the length
				// of the match must always be decoded next.
				model = is_rep1_model(model_base, state);
				rc_if_0(model) {
					// The distance is rep1.
					rc_update_0(model);

					const uint32_t distance = rep1;
					rep1 = rep0;
					rep0 = distance;

				} else {
					rc_update_1(model);

					model = is_rep2_model(model_base, state);
					rc_if_0(model) {
						// The distance is rep2.
						rc_update_0(model);

						const uint32_t distance = rep2;
						rep2 = rep1;
						rep1 = rep0;
						rep0 = distance;

					} else {
						// The distance is rep3.
						rc_update_1(model);

						const uint32_t distance = rep3;
						rep3 = rep2;
						rep2 = rep1;
						rep1 = rep0;
						rep0 = distance;
					}
				}
			}

			update_long_rep(state);

			// Decode the length of the repeated match.
			len_decode_fast(len, rep_length_model(model_base), pos_state);
		}

		/////////////////////////////////
		// Repeat from history buffer. //
		/////////////////////////////////

		// The length is always between these limits. There is no way
		// to trigger the algorithm to set len outside this range.
		assert(len >= MATCH_LEN_MIN);
		assert(len <= MATCH_LEN_MAX);

		// Repeat len bytes from distance of rep0.
		if (unlikely(dict_repeat(&dict, rep0, &len))) {
			coder->sequence = SEQ_COPY;
			goto out;
		}
		continue;
slow:
#endif
	///////////////////////////
	// Resumable Mode (slow) //
	///////////////////////////

	// This is very similar to Non-resumable Mode, so most of the
	// comments are not repeated. The main differences are:
	// - case labels are used to resume at the correct location.
	// - Loops are not unrolled.
	// - Range coder macros take an extra sequence argument
	//   so they can save to coder->sequence the location to
	//   resume in case there is not enough input.
	case SEQ_NORMALIZE:
	case SEQ_IS_MATCH:
		if (unlikely(might_finish_without_eopm
				&& dict.pos == dict.limit)) {
			// In rare cases there is a useless byte that needs
			// to be read anyway.
			rc_normalize_safe(SEQ_NORMALIZE);

			// If the range decoder state is such that we can
			// be at the end of the LZMA stream, then the
			// decoding is finished.
			if (rc_is_finished(rc)) {
				ret = LZMA_STREAM_END;
				goto out;
			}

			// If the caller hasn't allowed EOPM to be present
			// together with known uncompressed size, then the
			// LZMA stream is corrupt.
			if (!coder->allow_eopm) {
				ret = LZMA_DATA_ERROR;
				goto out;
			}

			// Otherwise continue decoding with the expectation
			// that the next LZMA symbol is EOPM.
			eopm_is_valid = true;
		}

		probs = is_match_model(model_base, pos_state, state);

		rc_if_0_safe(probs, SEQ_IS_MATCH) {
			/////////////////////
			// Decode literal. //
			/////////////////////

			rc_update_0(probs);

			probs = literal_subdecoder(literal_model(model_base),
					dict, literal_pos_mask,
					literal_context_bits);

			symbol = 1;

			if (is_literal_state(state)) {
				// Decode literal without match byte.
				// The "slow" version does not unroll
				// the loop.
	case SEQ_LITERAL:
				do {
					rc_bit_safe(probs + symbol, , ,
							SEQ_LITERAL);
				} while (symbol < (1 << 8));
			} else {
				// Decode literal with match byte.
				len = (uint32_t)(dict_get(&dict, rep0)) << 1;

				offset = 0x100;

	case SEQ_LITERAL_MATCHED:
				do {
					const uint32_t match_bit
							= len & offset;
					const uint32_t subcoder_index
							= offset + match_bit
							+ symbol;

					rc_bit_safe(probs + subcoder_index,
							offset &= ~match_bit,
							offset &= match_bit,
							SEQ_LITERAL_MATCHED);

					// It seems to be faster to do this
					// here instead of putting it to the
					// beginning of the loop and then
					// putting the "case" in the middle
					// of the loop.
					len <<= 1;

				} while (symbol < (1 << 8));
			}

			state = next_state[state];

	case SEQ_LITERAL_WRITE:
			if (dict_put_safe(&dict, symbol)) {
				coder->sequence = SEQ_LITERAL_WRITE;
				goto out;
			}

			continue;
		}

		///////////////////
		// Decode match. //
		///////////////////

		rc_update_1(probs);
		probs = is_rep_model(model_base, state);

	case SEQ_IS_REP:
		rc_if_0_safe(probs, SEQ_IS_REP) {
			///////////////////
			// Simple match. //
			///////////////////

			rc_update_0(probs);
			update_match(state);

			rep3 = rep2;
			rep2 = rep1;
			rep1 = rep0;

			probs = match_length_model(model_base);

			len_decode(len, probs, match_length_model(model_base),
					pos_state, SEQ_MATCH_LEN);

			probs = dist_slot_model(model_base)
				+ (get_dist_state(len) << DIST_SLOT_BITS);
			symbol = 1;

	case SEQ_DIST_SLOT:
			do {
				rc_bit_safe(probs + symbol, , , SEQ_DIST_SLOT);
			} while (symbol < DIST_SLOTS);

			symbol -= DIST_SLOTS;
			assert(symbol <= 63);

			if (symbol < DIST_MODEL_START) {
				rep0 = symbol;
			} else {
				limit = (symbol >> 1) - 1;
				assert(limit >= 1 && limit <= 30);
				rep0 = 2 + (symbol & 1);

				if (symbol < DIST_MODEL_END) {
					assert(limit <= 5);
					rep0 <<= limit;
					assert(rep0 <= 96);
					// -1 is fine, because we start
					// decoding at probs[1], not probs[0].
					// NOTE: This violates the C standard,
					// since we are doing pointer
					// arithmetic past the beginning of
					// the array.
					assert((int32_t)(rep0 - symbol - 1)
							>= -1);
					assert((int32_t)(rep0 - symbol - 1)
							<= 82);

					probs = pos_special_model(model_base) + rep0
							- symbol - 1;
					symbol = 1;
					offset = 0;
	case SEQ_DIST_MODEL:
					do {
						rc_bit_safe(probs + symbol, ,
							rep0 += 1U << offset,
							SEQ_DIST_MODEL);
					} while (++offset < limit);
				} else {
					assert(symbol >= 14);
					assert(limit >= 6);
					limit -= ALIGN_BITS;
					assert(limit >= 2);
	case SEQ_DIRECT:
					do {
						rc_direct_safe(rep0,
								SEQ_DIRECT);
					} while (--limit > 0);

					rep0 <<= ALIGN_BITS;
					symbol = 1;

					offset = 0;
					probs = pos_align_model(model_base);
	case SEQ_ALIGN:
					do {
						rc_bit_safe(probs + symbol, ,
							rep0 += 1U << offset,
							SEQ_ALIGN);
					} while (++offset < ALIGN_BITS);

					// End of payload marker
					if (rep0 == UINT32_MAX) {
						if (!eopm_is_valid) {
							ret = LZMA_DATA_ERROR;
							goto out;
						}

	case SEQ_EOPM:
						rc_normalize_safe(SEQ_EOPM);
						ret = rc_is_finished(rc)
							? LZMA_STREAM_END
							: LZMA_DATA_ERROR;
						goto out;
					}
				}
			}

			if (unlikely(!dict_is_distance_valid(&dict, rep0))) {
				ret = LZMA_DATA_ERROR;
				goto out;
			}

		} else {
			/////////////////////
			// Repeated match. //
			/////////////////////

			rc_update_1(probs);

			if (unlikely(!dict_is_distance_valid(&dict, 0))) {
				ret = LZMA_DATA_ERROR;
				goto out;
			}

			probs = is_rep0_model(model_base, state);
	case SEQ_IS_REP0:
			rc_if_0_safe(probs, SEQ_IS_REP0) {
				rc_update_0(probs);
				probs = is_rep0_long_model(model_base, state, pos_state);
	case SEQ_IS_REP0_LONG:
				rc_if_0_safe(probs, SEQ_IS_REP0_LONG) {
					rc_update_0(probs);
					update_short_rep(state);

	case SEQ_SHORTREP:
					if (dict_put_safe(&dict,
							dict_get(&dict,
							rep0))) {
						coder->sequence = SEQ_SHORTREP;
						goto out;
					}

					continue;
				}

				rc_update_1(probs);

			} else {
				rc_update_1(probs);
				probs = is_rep1_model(model_base, state);
	case SEQ_IS_REP1:
				rc_if_0_safe(probs, SEQ_IS_REP1) {
					rc_update_0(probs);

					const uint32_t distance = rep1;
					rep1 = rep0;
					rep0 = distance;

				} else {
					rc_update_1(probs);
					probs = is_rep2_model(model_base, state);
	case SEQ_IS_REP2:
					rc_if_0_safe(probs, SEQ_IS_REP2) {
						rc_update_0(probs);

						const uint32_t distance = rep2;
						rep2 = rep1;
						rep1 = rep0;
						rep0 = distance;

					} else {
						rc_update_1(probs);

						const uint32_t distance = rep3;
						rep3 = rep2;
						rep2 = rep1;
						rep1 = rep0;
						rep0 = distance;
					}
				}
			}

			update_long_rep(state);

			probs = rep_length_model(model_base);
			len_decode(len, probs, rep_length_model(model_base), pos_state, SEQ_REP_LEN);

		}

		/////////////////////////////////
		// Repeat from history buffer. //
		/////////////////////////////////

		assert(len >= MATCH_LEN_MIN);
		assert(len <= MATCH_LEN_MAX);

	case SEQ_COPY:
		if (unlikely(dict_repeat(&dict, rep0, &len))) {
			coder->sequence = SEQ_COPY;
			goto out;
		}
	}

out:
	// Save state

	// NOTE: Must not copy dict.limit.
	dictptr->pos = dict.pos;
	dictptr->full = dict.full;

	rc_from_local(coder->rc, *in_pos);

	coder->state = state;
	coder->rep0 = rep0;
	coder->rep1 = rep1;
	coder->rep2 = rep2;
	coder->rep3 = rep3;

	coder->probs = probs;
	coder->symbol = symbol;
	coder->limit = limit;
	coder->offset = offset;
	coder->len = len;

	// Update the remaining amount of uncompressed data if uncompressed
	// size was known.
	if (coder->uncompressed_size != LZMA_VLI_UNKNOWN) {
		coder->uncompressed_size -= dict.pos - dict_start;

		// If we have gotten all the output but the decoder wants
		// to write more output, the file is corrupt. There are
		// three SEQ values where output is produced.
		if (coder->uncompressed_size == 0 && ret == LZMA_OK
				&& (coder->sequence == SEQ_LITERAL_WRITE
					|| coder->sequence == SEQ_SHORTREP
					|| coder->sequence == SEQ_COPY))
			ret = LZMA_DATA_ERROR;
	}

	if (ret == LZMA_STREAM_END) {
		// Reset the range decoder so that it is ready to reinitialize
		// for a new LZMA2 chunk.
		rc_reset(coder->rc);
		coder->sequence = SEQ_IS_MATCH;
	}

	return ret;
}


static void
lzma_decoder_uncompressed(void *coder_ptr, lzma_vli uncompressed_size,
		bool allow_eopm)
{
	lzma_lzma1_decoder *coder = coder_ptr;
	coder->uncompressed_size = uncompressed_size;
	coder->allow_eopm = allow_eopm;
}


static void
lzma_decoder_reset(void *coder_ptr, const void *opt)
{
	lzma_lzma1_decoder *coder = coder_ptr;
	const lzma_options_lzma *options = opt;

	// NOTE: We assume that lc/lp/pb are valid since they were
	// successfully decoded with lzma_lzma_decode_properties().

	// Calculate pos_mask. We don't need pos_bits as is for anything.
	coder->pos_mask = (1U << options->pb) - 1;

	coder->literal_context_bits = options->lc;
	coder->literal_pos_mask = ((uint32_t) 0x100 << options->lp)
			- ((uint32_t) 0x100 >> options->lc);

	// State
	coder->state = STATE_LIT_LIT;
	coder->rep0 = 0;
	coder->rep1 = 0;
	coder->rep2 = 0;
	coder->rep3 = 0;
	coder->pos_mask = (1U << options->pb) - 1;

	// Range decoder
	rc_reset(coder->rc);

	// Init probabilities
	for (uint32_t i = 0; i < PROBABILITY_COUNT; i++)
		bit_reset(coder->model[i]);

	coder->sequence = SEQ_IS_MATCH;
	coder->probs = NULL;
	coder->symbol = 0;
	coder->limit = 0;
	coder->offset = 0;
	coder->len = 0;

	return;
}


extern lzma_ret
lzma_lzma_decoder_create(lzma_lz_decoder *lz, const lzma_allocator *allocator,
		const lzma_options_lzma *options, lzma_lz_options *lz_options)
{
	if (lz->coder == NULL) {
		lz->coder = lzma_alloc(sizeof(lzma_lzma1_decoder), allocator);
		if (lz->coder == NULL)
			return LZMA_MEM_ERROR;

		lz->code = &lzma_decode;
		lz->reset = &lzma_decoder_reset;
		lz->set_uncompressed = &lzma_decoder_uncompressed;
	}

	// All dictionary sizes are OK here. LZ decoder will take care of
	// the special cases.
	lz_options->dict_size = options->dict_size;
	lz_options->preset_dict = options->preset_dict;
	lz_options->preset_dict_size = options->preset_dict_size;

	return LZMA_OK;
}


/// Allocate and initialize LZMA decoder. This is used only via LZ
/// initialization (lzma_lzma_decoder_init() passes function pointer to
/// the LZ initialization).
static lzma_ret
lzma_decoder_init(lzma_lz_decoder *lz, const lzma_allocator *allocator,
		lzma_vli id, const void *options, lzma_lz_options *lz_options)
{
	if (!is_lclppb_valid(options))
		return LZMA_PROG_ERROR;

	lzma_vli uncomp_size = LZMA_VLI_UNKNOWN;
	bool allow_eopm = true;

	if (id == LZMA_FILTER_LZMA1EXT) {
		const lzma_options_lzma *opt = options;

		// Only one flag is supported.
		if (opt->ext_flags & ~LZMA_LZMA1EXT_ALLOW_EOPM)
			return LZMA_OPTIONS_ERROR;

		// FIXME? Using lzma_vli instead of uint64_t is weird because
		// this has nothing to do with .xz headers and variable-length
		// integer encoding. On the other hand, using LZMA_VLI_UNKNOWN
		// instead of UINT64_MAX is clearer when unknown size is
		// meant. A problem with using lzma_vli is that now we
		// allow > LZMA_VLI_MAX which is fine in this file but
		// it's still confusing. Note that alone_decoder.c also
		// allows > LZMA_VLI_MAX when setting uncompressed size.
		uncomp_size = opt->ext_size_low
				+ ((uint64_t)(opt->ext_size_high) << 32);
		allow_eopm = (opt->ext_flags & LZMA_LZMA1EXT_ALLOW_EOPM) != 0
				|| uncomp_size == LZMA_VLI_UNKNOWN;
	}

	return_if_error(lzma_lzma_decoder_create(
			lz, allocator, options, lz_options));

	lzma_decoder_reset(lz->coder, options);
	lzma_decoder_uncompressed(lz->coder, uncomp_size, allow_eopm);

	return LZMA_OK;
}


extern lzma_ret
lzma_lzma_decoder_init(lzma_next_coder *next, const lzma_allocator *allocator,
		const lzma_filter_info *filters)
{
	// LZMA can only be the last filter in the chain. This is enforced
	// by the raw_decoder initialization.
	assert(filters[1].init == NULL);

	return lzma_lz_decoder_init(next, allocator, filters,
			&lzma_decoder_init);
}


extern bool
lzma_lzma_lclppb_decode(lzma_options_lzma *options, uint8_t byte)
{
	if (byte > (4 * 5 + 4) * 9 + 8)
		return true;

	// See the file format specification to understand this.
	options->pb = byte / (9 * 5);
	byte -= options->pb * 9 * 5;
	options->lp = byte / 9;
	options->lc = byte - options->lp * 9;

	return options->lc + options->lp > LZMA_LCLP_MAX;
}


extern uint64_t
lzma_lzma_decoder_memusage_nocheck(const void *options)
{
	const lzma_options_lzma *const opt = options;
	return sizeof(lzma_lzma1_decoder)
			+ lzma_lz_decoder_memusage(opt->dict_size);
}


extern uint64_t
lzma_lzma_decoder_memusage(const void *options)
{
	if (!is_lclppb_valid(options))
		return UINT64_MAX;

	return lzma_lzma_decoder_memusage_nocheck(options);
}


extern lzma_ret
lzma_lzma_props_decode(void **options, const lzma_allocator *allocator,
		const uint8_t *props, size_t props_size)
{
	if (props_size != 5)
		return LZMA_OPTIONS_ERROR;

	lzma_options_lzma *opt
			= lzma_alloc(sizeof(lzma_options_lzma), allocator);
	if (opt == NULL)
		return LZMA_MEM_ERROR;

	if (lzma_lzma_lclppb_decode(opt, props[0]))
		goto error;

	// All dictionary sizes are accepted, including zero. LZ decoder
	// will automatically use a dictionary at least a few KiB even if
	// a smaller dictionary is requested.
	opt->dict_size = read32le(props + 1);

	opt->preset_dict = NULL;
	opt->preset_dict_size = 0;

	*options = opt;

	return LZMA_OK;

error:
	lzma_free(opt, allocator);
	return LZMA_OPTIONS_ERROR;
}
