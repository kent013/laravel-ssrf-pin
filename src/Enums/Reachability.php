<?php

declare(strict_types=1);

namespace Kent013\SsrfPin\Enums;

/**
 * IP アドレスの到達性分類（v0.4 / 完全区間分類）。
 *
 * **許可されるのは `PublicUnicast` だけである。** `NotGloballyReachable` と
 * `Unclassified` はいずれも拒否に倒す（既定拒否）。
 */
enum Reachability
{
    /** 分類表が「公開到達可能」と明示している区間に当たった。 */
    case PublicUnicast;

    /** 分類表が「公開到達不可」と明示している区間に当たった。 */
    case NotGloballyReachable;

    /**
     * どの区間にも当たらなかった / 正準な IP 表記ではなかった。
     *
     * 分類表が全空間を覆っている限り、正準な IP がここに落ちることは無い。
     * 落ちたときは表が壊れているので拒否する（黙って通さない）。
     */
    case Unclassified;
}
