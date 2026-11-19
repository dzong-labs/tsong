# Governance

Tsong has one maintainer, Mark Lauter ([@marklauter](https://github.com/marklauter)), who makes the project's decisions. This file says how decisions are made, who holds which role, and how the project continues if the maintainer can't.

## How decisions are made

- A bug report or a concrete request is an [issue](https://github.com/marklauter/tsong/issues). A question, or an idea that isn't a request yet, is a [discussion](https://github.com/marklauter/tsong/discussions).
- A design change is agreed in its issue before code is written, as [CONTRIBUTING.md](CONTRIBUTING.md) asks. The maintainer decides, giving the reasons in the issue.
- Every change reaches `main` through a pull request that passes CI's required checks. The maintainer decides whether it merges.
- [ROADMAP.md](ROADMAP.md) records what is planned for the next year and what is not planned. The maintainer changes it as plans change.

## Roles

- **Maintainer:** Mark Lauter. Reviews and merges pull requests, sets the roadmap, triages issues and discussions, receives and handles vulnerability reports as [SECURITY.md](SECURITY.md) describes, enforces the [code of conduct](CODE_OF_CONDUCT.md), and publishes releases. Holds admin access to the repository and owns the project's [OpenSSF Best Practices entry](https://www.bestpractices.dev/projects/16914).
- **Contributor:** anyone who opens an issue, a discussion or a pull request, following [CONTRIBUTING.md](CONTRIBUTING.md) and the code of conduct.

A contributor with a record of accepted changes can be invited to become a maintainer. With a second maintainer, pull requests will need an approving review from a maintainer other than their author.

## Continuity

The project can continue if the maintainer dies, is incapacitated, or stops working on it:

- **Successor.** The maintainer has designated a successor in GitHub's successor settings. If the maintainer can't act, the successor can claim the repository and its issues, pull requests, discussions and settings, and with them the right to merge, release and appoint maintainers.
- **No private signing keys.** Nothing the project publishes depends on a key only the maintainer holds. CI builds and checks every change, and needs only the repository.
- **Everything is in the repository.** The code, CI workflows, docs, roadmap and release history are public on GitHub, so anyone can fork the project and continue it.
