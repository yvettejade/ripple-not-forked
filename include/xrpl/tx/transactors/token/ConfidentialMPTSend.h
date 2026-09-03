#pragma once

#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/Transactor.h>

#include <cstddef>

namespace xrpl {

/** ConfidentialMPTSend — XLS-0096 confidential holder-to-holder transfer. */
class ConfidentialMPTSend : public Transactor
{
public:
    static constexpr auto kConsequencesFactory = ConsequencesFactoryType::Normal;

    /** Compact Send sigma proof size (6 scalars). */
    static constexpr std::size_t kSendSigmaProofBytes = 192;

    /** Aggregated Bulletproof size for Send (two 64-bit values). */
    static constexpr std::size_t kAggregatedBulletproofBytes = 754;

    /** Compact sigma (192) + aggregated Bulletproof (754). */
    static constexpr std::size_t kZKProofBytes = kSendSigmaProofBytes + kAggregatedBulletproofBytes;

    explicit ConfidentialMPTSend(ApplyContext& ctx) : Transactor(ctx)
    {
    }

    static bool
    checkExtraFeatures(PreflightContext const& ctx);

    static XRPAmount
    calculateBaseFee(ReadView const& view, STTx const& tx);

    static NotTEC
    preflight(PreflightContext const& ctx);

    static TER
    preclaim(PreclaimContext const& ctx);

    TER
    doApply() override;

    void
    visitInvariantEntry(
        bool isDelete,
        std::shared_ptr<SLE const> const& before,
        std::shared_ptr<SLE const> const& after) override;

    [[nodiscard]] bool
    finalizeInvariants(
        STTx const& tx,
        TER result,
        XRPAmount fee,
        ReadView const& view,
        beast::Journal const& j) override;
};

}  // namespace xrpl
