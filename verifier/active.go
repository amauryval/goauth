package verifier

import (
	"context"
	"errors"
	"time"
)

// activeMarker is what a cached introspection holds. The answer is a yes or nothing at all:
// a token the issuer called dead is never cached, so it cannot come back to life from here.
var activeMarker = []string{"active"}

// stillActive asks the issuer whether the token is one it still stands behind.
//
// A valid signature and an unexpired token say only that the issuer minted this, and when. They
// cannot say that the account still exists, that its password was not changed, or that the session
// was not ended: those are things only the issuer knows, and this is where it is asked.
//
// An issuer that cannot be reached is not an issuer saying no. It yields types.ErrAuthorization,
// answered with a 503, so an outage reads as an outage rather than as everyone being revoked at
// once.
func (v *Verifier) stillActive(ctx context.Context, rawToken string) error {
	if v.introspector == nil {
		return nil
	}

	now := v.now()
	if _, cached := v.introspections.get(rawToken, now); cached {
		return nil
	}

	answer, err := v.introspector.active(ctx, rawToken)
	if err != nil {
		v.logger.Error("auth: the issuer could not be asked about this token", "error", err)

		return err
	}

	if !answer.Active {
		v.logger.Warn("auth: the issuer no longer stands behind this token")

		return errors.New("the issuer no longer considers this token active")
	}

	v.introspections.put(rawToken, activeMarker, introspectionExpiry(answer), now)

	return nil
}

// introspectionExpiry reads the token expiry the issuer stated, so a cached answer never outlives
// the token it was given for.
func introspectionExpiry(answer introspection) time.Time {
	expiry, stated := answer.Claims["exp"].(float64)
	if !stated {
		return time.Time{}
	}

	return time.Unix(int64(expiry), 0)
}
