package types

type Provider int

const (
	GITHUB Provider = iota
	FACEBOOK
	GOOGLE
	SPOTIFY
	APPLE
	METAMASK
)

func (p Provider) String() string {
	return [...]string{"GITHUB", "FACEBOOK", "GOOGLE", "SPOTIFY", "APPLE", "METAMASK"}[p]
}
